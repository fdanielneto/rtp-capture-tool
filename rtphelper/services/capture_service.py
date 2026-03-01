from __future__ import annotations

import datetime as dt
import json
import logging
import os
import queue
import re
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rtphelper.config_loader import AppConfig, HostConfig
from rtphelper.logging_setup import short_uuid
from rtphelper.rpcap.frame_normalizer import normalize_link_layer_frame
from rtphelper.rpcap.pcap_writer import RollingPcapWriter
from rtphelper.size_parser import parse_size_bytes
from rtphelper.services.rpcap_client import RpcapClient
from rtphelper.services.s3_storage import S3CaptureStorage, S3Config

LOGGER = logging.getLogger(__name__)

DEFAULT_ROLLING_PCAP_MAX_BYTES = 500 * 1000 * 1000
DEFAULT_ROLLING_PCAP_MAX_SECONDS = 0
DEFAULT_SNAPLEN = 262144
LIVE_UPLOAD_ROLLED_SIZE_MARGIN_BYTES = 1 * 1024 * 1024
REACHABILITY_TTL_SECONDS = 30
REACHABILITY_MAX_WORKERS = 16
DEFAULT_LOCAL_SPOOL_MAX_BYTES = 5 * 1024 * 1024 * 1024
S3_MAINTENANCE_INTERVAL_SECONDS = 2.0
S3_MAINTENANCE_MAX_FILES_ACTIVE = max(
    1, int(os.environ.get("RTPHELPER_S3_MAINTENANCE_MAX_FILES_ACTIVE", "50") or "50")
)
_ROLLING_FILE_RE = re.compile(r"^(?P<prefix>.+)-(?P<seq>\d{4})\.(pcap|pcapng)$", re.IGNORECASE)
_IMPORT_NAME_RE = re.compile(r"^(?P<prefix>.+)-\d{4}\.(pcap|pcapng)$", re.IGNORECASE)
S3_POOL_CAPTURE = max(1, int(os.environ.get("RTPHELPER_S3_POOL_CAPTURE", "6") or "6"))
S3_POOL_POST_CAPTURE = max(1, int(os.environ.get("RTPHELPER_S3_POOL_POST_CAPTURE", "60") or "60"))
S3_UPLOAD_WORKERS_MAX = max(1, int(os.environ.get("RTPHELPER_S3_UPLOAD_WORKERS_MAX", "6") or "6"))
S3_UPLOAD_CONCURRENCY_CAPTURE = max(1, int(os.environ.get("RTPHELPER_S3_UPLOAD_CONCURRENCY_CAPTURE", "2") or "2"))
S3_UPLOAD_CONCURRENCY_POST_CAPTURE = max(1, int(os.environ.get("RTPHELPER_S3_UPLOAD_CONCURRENCY_POST_CAPTURE", "4") or "4"))
S3_UPLOAD_MAX_ATTEMPTS = max(1, int(os.environ.get("RTPHELPER_S3_UPLOAD_MAX_ATTEMPTS", "5") or "5"))
RPCAP_RECONNECT_BASE_SECONDS = max(1.0, float(os.environ.get("RTPHELPER_RPCAP_RECONNECT_BASE_SECONDS", "2") or "2"))
RPCAP_RECONNECT_MAX_SECONDS = max(
    RPCAP_RECONNECT_BASE_SECONDS,
    float(os.environ.get("RTPHELPER_RPCAP_RECONNECT_MAX_SECONDS", "30") or "30"),
)
RPCAP_RECONNECT_MAX_ATTEMPTS = max(0, int(os.environ.get("RTPHELPER_RPCAP_RECONNECT_MAX_ATTEMPTS", "3") or "3"))


def _rolling_pcap_max_bytes() -> int:
    return parse_size_bytes(
        os.environ.get("RTPHELPER_ROLLING_PCAP_MAX_BYTES", ""),
        DEFAULT_ROLLING_PCAP_MAX_BYTES,
    )


def _rolling_pcap_max_seconds() -> int:
    raw = os.environ.get("RTPHELPER_ROLLING_PCAP_MAX_SECONDS", "").strip()
    if raw:
        try:
            val = int(raw)
            if val >= 0:
                return val
        except Exception:
            pass
    return DEFAULT_ROLLING_PCAP_MAX_SECONDS


@dataclass
class HostCaptureWorker:
    host: HostConfig
    interface: str
    thread: threading.Thread


@dataclass
class CaptureSession:
    session_id: str
    environment: str
    region: str
    sub_regions: List[str]
    bpf_filter: str
    base_dir: Path
    raw_dir: Path
    uploads_dir: Path
    decrypted_dir: Path
    started_at: dt.datetime
    stopped_at: Optional[dt.datetime] = None
    running: bool = True
    failed: bool = False
    failure_reason: Optional[str] = None
    stop_reason: Optional[str] = None
    timeout_minutes: Optional[int] = None
    timeout_at: Optional[dt.datetime] = None
    host_errors: Dict[str, str] = field(default_factory=dict)

    stop_event: threading.Event = field(default_factory=threading.Event)
    host_workers: Dict[str, List[HostCaptureWorker]] = field(default_factory=dict)
    host_files: Dict[str, List[Path]] = field(default_factory=dict)
    host_packet_counts: Dict[str, int] = field(default_factory=dict)
    s3_source_objects: Dict[str, List[str]] = field(default_factory=dict)  # host_id -> S3 object keys
    s3_source_session_prefix: Optional[str] = None

    # Post-capture workflow context
    last_sip_pcap: Optional[Path] = None
    last_call_id: Optional[str] = None
    storage_mode: str = "local"
    storage_notice: Optional[str] = None
    storage_error: Optional[str] = None
    uploaded_files: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    uploaded_objects: Dict[str, str] = field(default_factory=dict)
    local_spool_max_bytes: int = DEFAULT_LOCAL_SPOOL_MAX_BYTES
    output_dir_name: Optional[str] = None
    storage_flush_state: str = "idle"  # idle|queued|running|paused|completed|fallback_local|failed
    storage_flush_pending_files: int = 0
    storage_flush_enqueued_at: Optional[dt.datetime] = None
    storage_flush_started_at: Optional[dt.datetime] = None
    storage_flush_finished_at: Optional[dt.datetime] = None
    storage_flush_error: Optional[str] = None
    storage_flush_attempts: int = 0
    storage_flush_current_file: Optional[str] = None
    source_mode: str = "capture"  # capture|import_upload|local_reference|s3_reference
    raw_dir_managed: bool = True


class CaptureService:
    def __init__(self, config: AppConfig, capture_root: Path) -> None:
        self._config = config
        self._capture_root = capture_root
        self._tmp_root = Path(os.environ.get("TMPDIR") or tempfile.gettempdir()).expanduser()
        self._storage_cfg = S3Config.from_env()
        self._s3 = S3CaptureStorage(self._storage_cfg)
        self._active_session: Optional[CaptureSession] = None
        self._latest_session: Optional[CaptureSession] = None
        self._maintenance_threads: Dict[str, threading.Thread] = {}
        self._sessions_by_id: Dict[str, CaptureSession] = {}
        self._storage_flush_queue: queue.Queue[str] = queue.Queue()
        self._storage_flush_queue_seen: set[str] = set()
        self._storage_flush_stop = threading.Event()
        self._storage_flush_worker = threading.Thread(
            target=self._storage_flush_loop,
            name="storage-flush-worker",
            daemon=True,
        )
        self._storage_flush_worker.start()
        self._s3_journal_path = Path("logs/s3_upload_journal.json")
        self._s3_journal_lock = threading.Lock()
        self._s3_journal: Dict[str, Dict[str, object]] = {}
        self._s3_journal_queue: queue.Queue[str] = queue.Queue()
        self._s3_journal_seen: set[str] = set()
        self._s3_journal_stop = threading.Event()
        self._s3_upload_mode_lock = threading.Lock()
        self._s3_upload_limit = S3_UPLOAD_CONCURRENCY_POST_CAPTURE
        self._s3_upload_active = 0
        self._s3_upload_cond = threading.Condition(self._s3_upload_mode_lock)
        self._flush_summary_last: Dict[str, Tuple[int, int, int]] = {}
        self._flush_pending_last_logged: Dict[str, int] = {}
        self._flush_pending_last_log_at: Dict[str, float] = {}
        self._load_s3_journal()
        self._s3_journal_workers: List[threading.Thread] = []
        for idx in range(S3_UPLOAD_WORKERS_MAX):
            worker = threading.Thread(
                target=self._s3_journal_loop,
                name=f"s3-journal-worker-{idx + 1}",
                daemon=True,
            )
            worker.start()
            self._s3_journal_workers.append(worker)
        self._reachability_lock = threading.Lock()
        self._reachability_at: float = 0.0
        self._reachability_at_by_env: Dict[str, float] = {}
        self._set_s3_pool_mode(capture_running=False)
        self._set_s3_upload_mode(capture_running=False)
        self._reachable_hosts: Dict[str, Dict[str, Dict[str, List[HostConfig]]]] = {}
        self._unreachable_hosts: Dict[str, Dict[str, Dict[str, Dict[str, str]]]] = {}

    @staticmethod
    def _host_key_from_capture_filename(filename: str) -> str:
        """Best-effort host key extraction for imported capture filenames."""
        name = Path(filename).name
        match = _IMPORT_NAME_RE.match(name)
        if not match:
            return "imported"
        prefix = match.group("prefix")
        return prefix or "imported"

    @property
    def local_spool_max_bytes(self) -> int:
        raw = os.environ.get("RTPHELPER_LOCAL_SPOOL_MAX_BYTES", "").strip()
        if raw:
            try:
                val = int(raw)
                if val > 0:
                    return val
            except Exception:
                pass
        return DEFAULT_LOCAL_SPOOL_MAX_BYTES

    def _build_storage_notice(self, reason: str) -> str:
        return (
            f"S3 unavailable ({reason}). Capture data is being written locally to {self._capture_root}."
        )

    def _session_storage_mode(self) -> Tuple[str, Optional[str]]:
        if not self._s3.enabled:
            return "local", None
        if not self._s3.configured:
            return "local", self._build_storage_notice("missing S3 configuration")
        # Do not require bucket-metadata permissions (e.g. GetBucketLocation/HeadBucket)
        # at startup. We validate S3 through actual object uploads and fallback on failure.
        return "s3", None

    def _set_s3_pool_mode(self, capture_running: bool) -> None:
        if not (self._s3.enabled and self._s3.configured):
            return
        target = S3_POOL_CAPTURE if capture_running else S3_POOL_POST_CAPTURE
        self._s3.set_max_pool_connections(target)

    def _set_s3_upload_mode(self, capture_running: bool) -> None:
        target = S3_UPLOAD_CONCURRENCY_CAPTURE if capture_running else S3_UPLOAD_CONCURRENCY_POST_CAPTURE
        with self._s3_upload_cond:
            if self._s3_upload_limit == target:
                return
            self._s3_upload_limit = target
            self._s3_upload_cond.notify_all()
        LOGGER.info(
            "S3 upload concurrency mode updated capture_running=%s limit=%s",
            capture_running,
            target,
            extra={"category": "CONFIG"},
        )

    def _acquire_s3_upload_slot(self) -> bool:
        with self._s3_upload_cond:
            while not self._s3_journal_stop.is_set() and self._s3_upload_active >= self._s3_upload_limit:
                self._s3_upload_cond.wait(timeout=0.5)
            if self._s3_journal_stop.is_set():
                return False
            self._s3_upload_active += 1
            return True

    def _release_s3_upload_slot(self) -> None:
        with self._s3_upload_cond:
            if self._s3_upload_active > 0:
                self._s3_upload_active -= 1
            self._s3_upload_cond.notify_all()

    def _session_base_key(self, session: CaptureSession) -> str:
        parts: List[str] = []
        if session.output_dir_name:
            parts.append(str(session.output_dir_name).strip("/"))
        parts.append(session.session_id)
        return "/".join([p for p in parts if p])

    def _remote_relative(self, session: CaptureSession, path: Path) -> str:
        env_segment = str(session.environment or "unknown").strip() or "unknown"
        base_key = self._session_base_key(session)
        try:
            if str(path.resolve()).startswith(str(session.raw_dir.resolve())):
                return f"{env_segment}/{base_key}/raw/{path.name}"
            if str(path.resolve()).startswith(str(session.uploads_dir.resolve())):
                return f"{env_segment}/{base_key}/uploads/{path.name}"
            if str(path.resolve()).startswith(str(session.decrypted_dir.resolve())):
                return f"{env_segment}/{base_key}/decrypted/{path.name}"
        except Exception:
            pass
        return f"{env_segment}/{base_key}/{path.name}"

    def _mark_storage_fallback(self, session: CaptureSession, reason: str) -> None:
        if session.storage_mode == "local" and session.storage_notice:
            return
        session.storage_mode = "local"
        session.storage_error = reason
        session.storage_notice = self._build_storage_notice(reason)
        LOGGER.warning(
            "S3 fallback activated session_id=%s reason=%s",
            session.session_id,
            reason,
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )

    def _pending_s3_files(self, session: CaptureSession, include_running: bool) -> int:
        if session.storage_mode != "s3":
            return 0
        pending_local_paths: set[str] = set()
        for local in self._s3_sync_candidates(session, include_running=include_running):
            if not local.is_file():
                continue
            try:
                stat = local.stat()
            except Exception:
                continue
            rel = self._remote_relative(session, local)
            fingerprint = (int(stat.st_size), int(stat.st_mtime_ns))
            if session.uploaded_files.get(rel) != fingerprint:
                pending_local_paths.add(str(local.resolve()))
        with self._s3_journal_lock:
            for local_path, entry in self._s3_journal.items():
                if str(entry.get("session_id") or "") != session.session_id:
                    continue
                status = str(entry.get("status") or "pending").lower()
                if status not in {"pending", "uploading"}:
                    continue
                pending_local_paths.add(str(local_path))
        return len(pending_local_paths)

    def _session_journal_counts(self, session_id: str) -> Tuple[int, int]:
        pending = 0
        uploading = 0
        with self._s3_journal_lock:
            for entry in self._s3_journal.values():
                if str(entry.get("session_id") or "") != session_id:
                    continue
                status = str(entry.get("status") or "pending").lower()
                if status == "pending":
                    pending += 1
                elif status == "uploading":
                    uploading += 1
        return pending, uploading

    def _session_journal_failed_count(self, session_id: str) -> int:
        failed = 0
        with self._s3_journal_lock:
            for entry in self._s3_journal.values():
                if str(entry.get("session_id") or "") != session_id:
                    continue
                status = str(entry.get("status") or "pending").lower()
                if status == "failed":
                    failed += 1
        return failed

    def _log_flush_cycle_summary(self, session: CaptureSession) -> None:
        pending, uploading = self._session_journal_counts(session.session_id)
        completed = len(session.uploaded_files)
        snapshot = (pending, uploading, completed)
        if self._flush_summary_last.get(session.session_id) == snapshot:
            return
        self._flush_summary_last[session.session_id] = snapshot
        LOGGER.info(
            "S3 flush cycle summary session_id=%s pending=%s uploading=%s completed=%s",
            session.session_id,
            pending,
            uploading,
            completed,
            extra={"category": "FILES", "correlation_id": session.session_id},
        )

    def _enqueue_storage_flush(self, session: CaptureSession, source: str) -> None:
        if session.storage_mode != "s3":
            session.storage_flush_state = "idle"
            session.storage_flush_pending_files = 0
            return
        if session.storage_flush_state == "paused" and source != "resume":
            session.storage_flush_pending_files = self._pending_s3_files(session, include_running=False)
            return
        session.storage_flush_state = "queued"
        session.storage_flush_enqueued_at = dt.datetime.utcnow()
        session.storage_flush_started_at = None
        session.storage_flush_finished_at = None
        session.storage_flush_error = None
        session.storage_flush_current_file = None
        session.storage_flush_pending_files = self._pending_s3_files(session, include_running=False)
        if session.session_id not in self._storage_flush_queue_seen:
            self._storage_flush_queue.put(session.session_id)
            self._storage_flush_queue_seen.add(session.session_id)
        LOGGER.info(
            "S3 final flush queued session_id=%s source=%s pending_files=%s",
            session.session_id,
            source,
            session.storage_flush_pending_files,
            extra={"category": "FILES", "correlation_id": session.session_id},
        )

    def _storage_flush_loop(self) -> None:
        LOGGER.info("Started storage flush worker", extra={"category": "CONFIG"})
        while not self._storage_flush_stop.is_set():
            try:
                session_id = self._storage_flush_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._storage_flush_queue_seen.discard(session_id)
            session = self._sessions_by_id.get(session_id)
            if session is None:
                continue
            if session.running:
                # Session resumed; let regular maintenance handle it.
                continue
            if session.storage_flush_state == "paused":
                continue
            if session.storage_mode != "s3":
                session.storage_flush_state = "fallback_local"
                session.storage_flush_finished_at = dt.datetime.utcnow()
                session.storage_flush_pending_files = 0
                session.storage_flush_current_file = None
                continue
            session.storage_flush_state = "running"
            session.storage_flush_started_at = dt.datetime.utcnow()
            session.storage_flush_attempts += 1
            try:
                self.sync_session_storage(session, include_running=False, force=False)
                self._log_flush_cycle_summary(session)
                pending = self._pending_s3_files(session, include_running=False)
                session.storage_flush_pending_files = pending
                failed_count = self._session_journal_failed_count(session.session_id)
                if session.storage_mode != "s3":
                    session.storage_flush_state = "fallback_local"
                    session.storage_flush_error = session.storage_error or "S3 fallback activated"
                    session.storage_flush_finished_at = dt.datetime.utcnow()
                    session.storage_flush_current_file = None
                    self._flush_pending_last_logged.pop(session.session_id, None)
                    self._flush_pending_last_log_at.pop(session.session_id, None)
                    LOGGER.warning(
                        "S3 final flush switched to local fallback session_id=%s reason=%s",
                        session.session_id,
                        session.storage_flush_error,
                        extra={"category": "FILES", "correlation_id": session.session_id},
                    )
                    continue
                if pending > 0:
                    session.storage_flush_state = "queued"
                    session.storage_flush_error = f"{pending} file(s) pending after flush attempt"
                    session.storage_flush_current_file = None
                    if session.session_id not in self._storage_flush_queue_seen:
                        self._storage_flush_queue.put(session.session_id)
                        self._storage_flush_queue_seen.add(session.session_id)
                    now_ts = time.monotonic()
                    last_pending = self._flush_pending_last_logged.get(session.session_id)
                    last_log_at = self._flush_pending_last_log_at.get(session.session_id, 0.0)
                    if last_pending != pending or (now_ts - last_log_at) >= 30.0:
                        LOGGER.warning(
                            "S3 final flush pending session_id=%s pending_files=%s checking",
                            session.session_id,
                            pending,
                            extra={"category": "FILES", "correlation_id": session.session_id},
                        )
                        self._flush_pending_last_logged[session.session_id] = pending
                        self._flush_pending_last_log_at[session.session_id] = now_ts
                    time.sleep(0.5)
                    continue
                if failed_count > 0:
                    session.storage_flush_state = "failed"
                    session.storage_flush_error = (
                        f"S3 upload failed for {failed_count} file(s) after {S3_UPLOAD_MAX_ATTEMPTS} attempts. "
                        f"Temporary files remain in: {self._tmp_root}"
                    )
                    session.storage_flush_finished_at = dt.datetime.utcnow()
                    session.storage_flush_current_file = None
                    self._flush_pending_last_logged.pop(session.session_id, None)
                    self._flush_pending_last_log_at.pop(session.session_id, None)
                    LOGGER.error(
                        "S3 final flush failed session_id=%s failed_files=%s max_attempts=%s tmp_root=%s",
                        session.session_id,
                        failed_count,
                        S3_UPLOAD_MAX_ATTEMPTS,
                        self._tmp_root,
                        extra={"category": "FILES", "correlation_id": session.session_id},
                    )
                    continue
                session.storage_flush_state = "completed"
                session.storage_flush_error = None
                session.storage_flush_finished_at = dt.datetime.utcnow()
                session.storage_flush_current_file = None
                self._flush_pending_last_logged.pop(session.session_id, None)
                self._flush_pending_last_log_at.pop(session.session_id, None)
                self._log_flush_cycle_summary(session)
                LOGGER.info(
                    "S3 final flush completed session_id=%s attempts=%s",
                    session.session_id,
                    session.storage_flush_attempts,
                    extra={"category": "FILES", "correlation_id": session.session_id},
                )
            except Exception as exc:
                session.storage_flush_state = "queued"
                session.storage_flush_error = str(exc)
                session.storage_flush_current_file = None
                if session.session_id not in self._storage_flush_queue_seen:
                    self._storage_flush_queue.put(session.session_id)
                    self._storage_flush_queue_seen.add(session.session_id)
                LOGGER.warning(
                    "S3 final flush attempt failed session_id=%s reason=%s",
                    session.session_id,
                    exc,
                    extra={"category": "FILES", "correlation_id": session.session_id},
                )
                time.sleep(2.0)
        LOGGER.info("Stopped storage flush worker", extra={"category": "CONFIG"})

    def storage_flush_status(self, session: CaptureSession) -> Dict[str, object]:
        failed_files = self._session_journal_failed_count(session.session_id)
        return {
            "state": session.storage_flush_state,
            "pending_files": int(session.storage_flush_pending_files),
            "attempts": int(session.storage_flush_attempts),
            "current_file": session.storage_flush_current_file,
            "enqueued_at": session.storage_flush_enqueued_at.isoformat() if session.storage_flush_enqueued_at else None,
            "started_at": session.storage_flush_started_at.isoformat() if session.storage_flush_started_at else None,
            "finished_at": session.storage_flush_finished_at.isoformat() if session.storage_flush_finished_at else None,
            "error": session.storage_flush_error,
            "failed_files": failed_files,
            "max_attempts": S3_UPLOAD_MAX_ATTEMPTS,
            "tmp_root": str(self._tmp_root),
        }

    def storage_flush_pause(self, session_id: str | None = None) -> Dict[str, object]:
        sid = (session_id or "").strip()
        session = self._sessions_by_id.get(sid) if sid else self._latest_session
        target_session_id = sid or (session.session_id if session else "")
        if not target_session_id:
            raise ValueError("No session available for flush pause")

        paused_pending = 0
        with self._s3_journal_lock:
            for local_path, entry in list(self._s3_journal.items()):
                if str(entry.get("session_id") or "") != target_session_id:
                    continue
                status = str(entry.get("status") or "pending").lower()
                if status in {"pending", "uploading"}:
                    entry["status"] = "paused"
                    entry["updated_at"] = dt.datetime.utcnow().isoformat()
                    self._s3_journal[local_path] = entry
                    paused_pending += 1
            self._save_s3_journal()

        if session is not None:
            session.storage_flush_state = "paused"
            session.storage_flush_pending_files = paused_pending
            session.storage_flush_current_file = None
            session.storage_flush_error = (
                f"Flush paused by user. Pending files remain in temporary directory: {self._tmp_root}"
            )
            return self.storage_flush_status(session)

        return {
            "state": "paused",
            "pending_files": paused_pending,
            "attempts": 0,
            "current_file": None,
            "enqueued_at": None,
            "started_at": None,
            "finished_at": None,
            "error": f"Flush paused by user. Pending files remain in temporary directory: {self._tmp_root}",
            "failed_files": 0,
            "max_attempts": S3_UPLOAD_MAX_ATTEMPTS,
            "tmp_root": str(self._tmp_root),
        }

    def storage_flush_resume(self, session_id: str) -> Dict[str, object]:
        sid = (session_id or "").strip()
        if not sid:
            raise ValueError("session_id is required to resume flush")
        session = self._sessions_by_id.get(sid)
        resumed_count = 0
        with self._s3_journal_lock:
            for local_path, entry in list(self._s3_journal.items()):
                if str(entry.get("session_id") or "") != sid:
                    continue
                status = str(entry.get("status") or "pending").lower()
                if status in {"paused", "failed"}:
                    entry["status"] = "pending"
                    if status == "failed":
                        entry["attempts"] = 0
                        entry.pop("last_error", None)
                    entry["updated_at"] = dt.datetime.utcnow().isoformat()
                    self._s3_journal[local_path] = entry
                    self._enqueue_s3_journal_entry(local_path)
                    resumed_count += 1
            self._save_s3_journal()

        if resumed_count <= 0:
            raise ValueError(f"No paused/failed files found for session {sid}")

        if session is not None:
            session.storage_flush_state = "queued"
            session.storage_flush_error = None
            session.storage_flush_enqueued_at = dt.datetime.utcnow()
            session.storage_flush_finished_at = None
            session.storage_flush_pending_files = self._pending_s3_files(session, include_running=False)
            if session.session_id not in self._storage_flush_queue_seen:
                self._storage_flush_queue.put(session.session_id)
                self._storage_flush_queue_seen.add(session.session_id)
            return self.storage_flush_status(session)

        return {
            "state": "queued",
            "pending_files": resumed_count,
            "attempts": 0,
            "current_file": None,
            "enqueued_at": dt.datetime.utcnow().isoformat(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "failed_files": 0,
            "max_attempts": S3_UPLOAD_MAX_ATTEMPTS,
            "tmp_root": str(self._tmp_root),
        }

    def s3_correlation_block_reason(self, session: CaptureSession) -> str | None:
        """
        Return a user-facing reason when correlation should be blocked due to pending S3 uploads.
        Applies only to S3 storage sessions.
        """
        if session.storage_mode != "s3":
            return None
        flush = self.storage_flush_status(session)
        state = str(flush.get("state") or "").strip().lower()
        pending = int(flush.get("pending_files") or 0)
        failed_files = int(flush.get("failed_files") or 0)
        if state in {"queued", "running", "paused", "failed"}:
            return (
                "Captures are still being saved to S3. "
                f"Pending files={pending if pending > 0 else (failed_files if failed_files > 0 else 'unknown')}. Please try again later."
            )

        # Real-time pending scan from current raw spool.
        try:
            pending_scan = self._pending_s3_files(session, include_running=False)
        except Exception:
            pending_scan = 0
        if pending_scan > 0:
            return (
                "Captures are still being saved to S3. "
                f"Pending files={pending_scan}. Please try again later."
            )

        # Pending persisted journal entries for this session.
        session_pending_journal = 0
        with self._s3_journal_lock:
            for entry in self._s3_journal.values():
                if str(entry.get("session_id") or "") != session.session_id:
                    continue
                status = str(entry.get("status") or "pending").lower()
                if status in {"pending", "paused", "failed"}:
                    session_pending_journal += 1
        if session_pending_journal > 0:
            return (
                "Captures are still being saved to S3. "
                f"Pending files={session_pending_journal}. Please try again later."
            )
        return None

    def shutdown(self) -> None:
        def _normalize_uploading_entries() -> None:
            with self._s3_journal_lock:
                dirty = False
                for local_path, entry in list(self._s3_journal.items()):
                    status = str(entry.get("status", "pending")).lower()
                    if status != "uploading":
                        continue
                    entry["status"] = "pending"
                    entry["updated_at"] = dt.datetime.utcnow().isoformat()
                    self._s3_journal[local_path] = entry
                    dirty = True
                if dirty:
                    self._save_s3_journal()

        _normalize_uploading_entries()
        self._storage_flush_stop.set()
        if self._storage_flush_worker.is_alive():
            self._storage_flush_worker.join(timeout=2.0)
        self._s3_journal_stop.set()
        with self._s3_upload_cond:
            self._s3_upload_cond.notify_all()
        for worker in self._s3_journal_workers:
            if worker.is_alive():
                worker.join(timeout=2.0)
        _normalize_uploading_entries()

    def _load_s3_journal(self) -> None:
        try:
            self._s3_journal_path.parent.mkdir(parents=True, exist_ok=True)
            if not self._s3_journal_path.exists():
                self._s3_journal = {}
                return
            raw = self._s3_journal_path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
            if not isinstance(data, dict):
                data = {}
            self._s3_journal = {
                str(k): v for k, v in data.items() if isinstance(v, dict)
            }
            dirty = False
            for local_path, entry in list(self._s3_journal.items()):
                status = str(entry.get("status", "pending")).lower()
                if status == "uploading":
                    entry["status"] = "pending"
                    self._s3_journal[local_path] = entry
                    dirty = True
                    status = "pending"
            if dirty:
                self._save_s3_journal()
            if self._s3_journal:
                LOGGER.info(
                    "Loaded S3 upload journal entries=%s pending=%s (auto-resume disabled)",
                    len(self._s3_journal),
                    sum(1 for v in self._s3_journal.values() if str(v.get("status", "pending")).lower() == "pending"),
                    extra={"category": "FILES"},
                )
        except Exception as exc:
            LOGGER.warning("Could not load S3 upload journal reason=%s", exc, extra={"category": "FILES"})
            self._s3_journal = {}

    def _save_s3_journal(self) -> None:
        tmp = self._s3_journal_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._s3_journal, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._s3_journal_path)

    def _enqueue_s3_journal_entry(self, local_path: str) -> None:
        if local_path in self._s3_journal_seen:
            return
        self._s3_journal_queue.put(local_path)
        self._s3_journal_seen.add(local_path)

    def _journal_track_upload(self, session: CaptureSession, local: Path, rel: str) -> bool:
        local_path = str(local.resolve())
        now = dt.datetime.utcnow().isoformat()
        size_bytes = 0
        mtime_ns = 0
        try:
            st = local.stat()
            size_bytes = int(st.st_size)
            mtime_ns = int(st.st_mtime_ns)
        except Exception:
            pass
        with self._s3_journal_lock:
            existing = self._s3_journal.get(local_path, {})
            existing_status = str(existing.get("status", "pending")).lower()
            if (
                existing
                and existing_status == "uploading"
                and str(existing.get("relative_file", "")).strip() == rel
                and str(existing.get("session_id", "")).strip() == session.session_id
            ):
                return False
            if (
                existing
                and existing_status in {"pending", "uploading", "paused", "failed"}
                and str(existing.get("relative_file", "")).strip() == rel
                and str(existing.get("session_id", "")).strip() == session.session_id
                and int(existing.get("size_bytes", 0) or 0) == size_bytes
                and int(existing.get("mtime_ns", 0) or 0) == mtime_ns
            ):
                return False
            prev_attempts = int(self._s3_journal.get(local_path, {}).get("attempts", 0) or 0)
            self._s3_journal[local_path] = {
                "status": "pending",
                "local_path": local_path,
                "relative_file": rel,
                "session_id": session.session_id,
                "created_at": self._s3_journal.get(local_path, {}).get("created_at") or now,
                "updated_at": now,
                "attempts": prev_attempts,
                "size_bytes": size_bytes,
                "mtime_ns": mtime_ns,
            }
            self._save_s3_journal()
            self._enqueue_s3_journal_entry(local_path)
            return True

    def _journal_mark_uploaded(self, local: Path) -> None:
        local_path = str(local.resolve())
        with self._s3_journal_lock:
            entry = self._s3_journal.get(local_path)
            if not entry:
                return
            entry["status"] = "uploaded"
            entry["updated_at"] = dt.datetime.utcnow().isoformat()
            self._s3_journal.pop(local_path, None)
            self._save_s3_journal()

    def _s3_journal_loop(self) -> None:
        LOGGER.info("Started S3 journal worker", extra={"category": "CONFIG"})
        while not self._s3_journal_stop.is_set():
            try:
                local_path = self._s3_journal_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._s3_journal_seen.discard(local_path)
            if not self._s3.enabled or not self._s3.configured:
                self._enqueue_s3_journal_entry(local_path)
                time.sleep(1.0)
                continue
            with self._s3_journal_lock:
                entry = dict(self._s3_journal.get(local_path, {}))
            if not entry:
                continue
            if str(entry.get("status", "pending")).lower() != "pending":
                continue
            attempts = int(entry.get("attempts", 0) or 0)
            if attempts >= S3_UPLOAD_MAX_ATTEMPTS:
                with self._s3_journal_lock:
                    curr = self._s3_journal.get(local_path, {})
                    if curr:
                        curr["status"] = "failed"
                        curr["updated_at"] = dt.datetime.utcnow().isoformat()
                        self._s3_journal[local_path] = curr
                        self._save_s3_journal()
                continue
            relative_file = str(entry.get("relative_file", "")).strip()
            if not relative_file:
                continue
            local = Path(local_path)
            if not local.exists():
                with self._s3_journal_lock:
                    self._s3_journal.pop(local_path, None)
                    self._save_s3_journal()
                continue
            try:
                acquired_slot = False
                with self._s3_journal_lock:
                    curr = dict(self._s3_journal.get(local_path, {}))
                    if not curr:
                        continue
                    curr["status"] = "uploading"
                    curr["updated_at"] = dt.datetime.utcnow().isoformat()
                    self._s3_journal[local_path] = curr
                    self._save_s3_journal()
                if not self._acquire_s3_upload_slot():
                    self._enqueue_s3_journal_entry(local_path)
                    continue
                acquired_slot = True
                session_id = str(entry.get("session_id") or "")
                session = self._sessions_by_id.get(session_id)
                if session is not None:
                    session.storage_flush_current_file = local.name
                upload_started_at = time.monotonic()
                self._s3.upload_file(local, relative_file)
                upload_elapsed_s = max(0.001, time.monotonic() - upload_started_at)
                key = self._s3.to_s3_key(relative_file)
                try:
                    st = local.stat()
                    fingerprint = (int(st.st_size), int(st.st_mtime_ns))
                except Exception:
                    fingerprint = None
                size_bytes = int(entry.get("size_bytes") or 0)
                if size_bytes <= 0 and fingerprint is not None:
                    size_bytes = int(fingerprint[0])
                upload_mib_s = (size_bytes / 1024 / 1024) / upload_elapsed_s if size_bytes > 0 else 0.0
                upload_mbps = (size_bytes * 8 / 1_000_000) / upload_elapsed_s if size_bytes > 0 else 0.0
                if session is not None and fingerprint is not None:
                    session.uploaded_files[relative_file] = fingerprint
                    session.uploaded_objects[relative_file] = key
                deleted_local = False
                try:
                    if session is None or self._should_delete_local_after_upload(session, local, include_running=False):
                        local.unlink(missing_ok=True)
                        deleted_local = True
                except Exception:
                    pass
                self._journal_mark_uploaded(local)
                self._cleanup_empty_dirs_after_upload(local.parent)
                if session is not None:
                    self._refresh_session_host_files(session)
                    self._cleanup_uploaded_raw_dirs(session)
                LOGGER.info(
                    (
                        "Raw segment uploaded to S3 session_id=%s file=%s size_bytes=%s key=%s "
                        "upload_seconds=%.3f upload_MiBps=%.3f upload_Mbps=%.3f"
                    ),
                    session_id or "-",
                    local.name,
                    size_bytes,
                    key,
                    upload_elapsed_s,
                    upload_mib_s,
                    upload_mbps,
                    extra={"category": "FILES", "correlation_id": session_id or "-"},
                )
                if deleted_local:
                    LOGGER.info(
                        "raw segment uploaded+purged event=raw_segment_uploaded_purged session_id=%s file=%s key=%s",
                        session_id or "-",
                        local.name,
                        key,
                        extra={"category": "FILES", "correlation_id": session_id or "-"},
                    )
                LOGGER.info(
                    "S3 upload committed session_id=%s file=%s key=%s",
                    session_id or "-",
                    local.name,
                    key,
                    extra={"category": "FILES", "correlation_id": session_id or "-"},
                )
            except Exception as exc:
                with self._s3_journal_lock:
                    curr = self._s3_journal.get(local_path, {})
                    curr["attempts"] = int(curr.get("attempts", 0) or 0) + 1
                    attempts = int(curr["attempts"])
                    curr["status"] = "failed" if attempts >= S3_UPLOAD_MAX_ATTEMPTS else "pending"
                    curr["updated_at"] = dt.datetime.utcnow().isoformat()
                    curr["last_error"] = str(exc)
                    self._s3_journal[local_path] = curr
                    self._save_s3_journal()
                if attempts >= S3_UPLOAD_MAX_ATTEMPTS:
                    session_id = str(entry.get("session_id") or "")
                    session = self._sessions_by_id.get(session_id)
                    if session is not None:
                        session.storage_flush_state = "failed"
                        session.storage_flush_error = (
                            f"S3 upload failed after {S3_UPLOAD_MAX_ATTEMPTS} attempts. "
                            f"Temporary files remain in: {self._tmp_root}"
                        )
                        session.storage_flush_finished_at = dt.datetime.utcnow()
                        session.storage_flush_current_file = None
                        session.storage_flush_pending_files = self._pending_s3_files(session, include_running=False)
                    LOGGER.error(
                        "S3 upload failed max attempts reached session_id=%s file=%s attempts=%s tmp_root=%s reason=%s",
                        session_id or "-",
                        local.name,
                        attempts,
                        self._tmp_root,
                        exc,
                        extra={"category": "FILES", "correlation_id": session_id or "-"},
                    )
                else:
                    time.sleep(1.0)
                    self._enqueue_s3_journal_entry(local_path)
            finally:
                try:
                    if session is not None:
                        session.storage_flush_current_file = None
                except Exception:
                    pass
                if acquired_slot:
                    self._release_s3_upload_slot()
        LOGGER.info("Stopped S3 journal worker", extra={"category": "CONFIG"})

    def _cleanup_empty_dirs_after_upload(self, start_dir: Path) -> None:
        curr = start_dir
        for _ in range(8):
            if not curr.exists():
                break
            try:
                if any(curr.iterdir()):
                    break
                curr.rmdir()
            except Exception:
                break
            curr = curr.parent

    def sync_session_storage(
        self,
        session: CaptureSession,
        include_running: bool = False,
        force: bool = False,
        max_files: int | None = None,
    ) -> None:
        if session.storage_mode != "s3":
            return
        files = self._s3_sync_candidates(session, include_running=include_running)
        if max_files is not None and max_files > 0:
            files = files[:max_files]
        try:
            enqueued = 0
            for local in files:
                if not local.is_file():
                    continue
                stat = local.stat()
                fingerprint = (int(stat.st_size), int(stat.st_mtime_ns))
                rel = self._remote_relative(session, local)
                if (not force) and session.uploaded_files.get(rel) == fingerprint:
                    continue
                tracked = self._journal_track_upload(session, local, rel)
                if not tracked:
                    continue
                enqueued += 1
                LOGGER.info(
                    "Queued raw segment for S3 upload session_id=%s file=%s size_bytes=%s bucket=%s key=%s",
                    session.session_id,
                    local.name,
                    int(stat.st_size),
                    self._s3.bucket,
                    self._s3.to_s3_key(rel),
                    extra={"category": "FILES", "correlation_id": session.session_id},
                )
            if enqueued > 0:
                LOGGER.info(
                    "S3 upload queue updated session_id=%s enqueued_files=%s",
                    session.session_id,
                    enqueued,
                    extra={"category": "FILES", "correlation_id": session.session_id},
                )
            # Keep session media indexes coherent with current S3 state for post-processing.
            self._refresh_session_host_files(session)
            self._cleanup_uploaded_raw_dirs(session)
        except Exception as exc:
            # Keep S3 mode active on upload failures and retry in the next maintenance/flush cycle.
            # Falling back to local immediately on a single-file transient error can leave the
            # session in local mode even when S3 is healthy moments later.
            session.storage_error = str(exc)
            LOGGER.warning(
                "S3 upload attempt failed session_id=%s reason=%s; keeping S3 mode and retrying",
                session.session_id,
                exc,
                extra={"category": "FILES", "correlation_id": session.session_id},
            )

    def _s3_sync_candidates(self, session: CaptureSession, include_running: bool) -> List[Path]:
        files: List[Path] = []
        raw_files = sorted(session.raw_dir.rglob("*.pcap*"))
        if include_running and session.running:
            latest_by_prefix: Dict[str, Tuple[int, Path]] = {}
            for path in raw_files:
                m = _ROLLING_FILE_RE.match(path.name)
                if not m:
                    continue
                prefix = m.group("prefix")
                seq = int(m.group("seq"))
                curr = latest_by_prefix.get(prefix)
                if curr is None or seq > curr[0]:
                    latest_by_prefix[prefix] = (seq, path)
            hot_files = {p for (_seq, p) in latest_by_prefix.values()}
            ready_files: List[Path] = []
            live_upload_target = _rolling_pcap_max_bytes()
            min_ready_size = max(24, live_upload_target - LIVE_UPLOAD_ROLLED_SIZE_MARGIN_BYTES)
            for path in raw_files:
                if path in hot_files:
                    continue
                try:
                    size_bytes = int(path.stat().st_size)
                except Exception:
                    continue
                if size_bytes < min_ready_size:
                    # Keep undersized rolled files local while capture is active.
                    # They are uploaded during final flush after stop.
                    continue
                ready_files.append(path)
            files.extend(ready_files)
        else:
            files.extend(raw_files)
        # Post-process artifacts are always local-only by requirement.
        # Do not upload uploads/decrypted/combined to S3.
        return files

    def _should_delete_local_after_upload(self, session: CaptureSession, local: Path, include_running: bool) -> bool:
        if session.storage_mode != "s3":
            return False
        # Remove only captured raw segments after successful S3 upload.
        # Post-process artifacts (uploads/decrypted/combined) are always local-only.
        try:
            return str(local.resolve()).startswith(str(session.raw_dir.resolve()))
        except Exception:
            return False

    def _cleanup_uploaded_raw_dirs(self, session: CaptureSession) -> None:
        """
        Once all raw capture segments are uploaded and purged locally, remove raw directory tree.
        Keep post-process directories/files (uploads/decrypted/combined) locally.
        """
        if session.storage_mode != "s3":
            return
        raw_dir = session.raw_dir
        if not raw_dir.exists():
            return
        if any(raw_dir.rglob("*.pcap*")):
            return
        try:
            shutil.rmtree(raw_dir, ignore_errors=True)
            LOGGER.info(
                "Local raw directory removed after S3 upload completion session_id=%s dir=%s",
                session.session_id,
                raw_dir,
                extra={"category": "FILES", "correlation_id": session.session_id},
            )
        except Exception as exc:
            LOGGER.warning(
                "Could not remove local raw directory after S3 upload completion session_id=%s dir=%s reason=%s",
                session.session_id,
                raw_dir,
                exc,
                extra={"category": "FILES", "correlation_id": session.session_id},
            )

    def _session_disk_usage_bytes(self, session: CaptureSession) -> int:
        total = 0
        roots = [session.base_dir]
        try:
            if str(session.raw_dir.resolve()) != str(session.base_dir.resolve()):
                roots.append(session.raw_dir)
        except Exception:
            roots.append(session.raw_dir)
        seen_roots = set()
        for root in roots:
            key = str(root)
            if key in seen_roots:
                continue
            seen_roots.add(key)
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    total += int(path.stat().st_size)
                except Exception:
                    continue
        return total

    def _enforce_spool_limit(self, session: CaptureSession) -> None:
        if session.storage_mode != "s3":
            return
        usage = self._session_disk_usage_bytes(session)
        if usage <= session.local_spool_max_bytes:
            return
        LOGGER.warning(
            "Local spool limit exceeded session_id=%s usage_bytes=%s limit_bytes=%s; forcing S3 sync",
            session.session_id,
            usage,
            session.local_spool_max_bytes,
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )
        self.sync_session_storage(session, include_running=True, force=True)
        # Give queued upload workers a short window to drain before deciding hard-fail.
        time.sleep(2.0)
        usage_after = self._session_disk_usage_bytes(session)
        if usage_after > session.local_spool_max_bytes:
            pending = self._pending_s3_files(session, include_running=True)
            if pending > 0 and usage_after <= int(session.local_spool_max_bytes * 1.2):
                LOGGER.warning(
                    "Local spool still above limit but uploads are in progress session_id=%s usage_bytes=%s limit_bytes=%s pending_files=%s",
                    session.session_id,
                    usage_after,
                    session.local_spool_max_bytes,
                    pending,
                    extra={"category": "CAPTURE", "correlation_id": session.session_id},
                )
                return
            raise RuntimeError(
                f"Local spool limit exceeded ({usage_after} > {session.local_spool_max_bytes}) while S3 sync is lagging"
            )

    def _start_s3_maintenance(self, session: CaptureSession) -> None:
        if session.storage_mode != "s3":
            return
        existing = self._maintenance_threads.get(session.session_id)
        if existing and existing.is_alive():
            return

        def _loop() -> None:
            LOGGER.info(
                "Started S3 maintenance loop session_id=%s interval_s=%s",
                session.session_id,
                S3_MAINTENANCE_INTERVAL_SECONDS,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )
            while not session.stop_event.is_set() and session.running:
                try:
                    self.sync_session_storage(
                        session,
                        include_running=True,
                        force=False,
                        max_files=S3_MAINTENANCE_MAX_FILES_ACTIVE,
                    )
                    self._enforce_spool_limit(session)
                except Exception as exc:
                    self._abort_active_session(session, reason=str(exc), host_id="storage")
                    break
                time.sleep(S3_MAINTENANCE_INTERVAL_SECONDS)
            LOGGER.info(
                "Stopped S3 maintenance loop session_id=%s",
                session.session_id,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )

        t = threading.Thread(target=_loop, name=f"s3-maint-{session.session_id}", daemon=True)
        t.start()
        self._maintenance_threads[session.session_id] = t

    def storage_target_hint(self, session: CaptureSession) -> str:
        if session.storage_mode == "s3":
            env_segment = str(session.environment or "unknown").strip() or "unknown"
            remote_base = f"{env_segment}/{self._session_base_key(session)}"
            return self._s3.format_location(remote_base)
        return str(session.base_dir)

    def file_reference(self, session: CaptureSession, path: Path) -> Optional[str]:
        if session.storage_mode != "s3":
            return None
        rel = self._remote_relative(session, path)
        key = session.uploaded_objects.get(rel)
        if not key:
            # If an object key is not tracked as uploaded, serve local download link.
            return None
        return self._s3.format_key_location(key)

    def list_environments(self) -> List[str]:
        return sorted(self._config.environments.keys())

    def list_regions(self, environment: str) -> List[str]:
        env_cfg = self._config.environments.get(environment)
        if env_cfg is None:
            return []
        return sorted(env_cfg.regions.keys())

    def list_sub_regions(self, environment: str, region: str) -> List[str]:
        env_cfg = self._config.environments.get(environment)
        if env_cfg is None:
            return []
        region_cfg = env_cfg.regions.get(region)
        if region_cfg is None:
            return []
        return sorted(region_cfg.sub_regions.keys())

    def _resolve_capture_scope(
        self,
        environment: str,
        name: str,
        sub_regions: list[str] | None = None,
    ) -> Tuple[str, List[str], List[Tuple[str, HostConfig]]]:
        """
        Resolve user-supplied capture scope.
        Accepts sub-region name directly, or a top-level region when it has one sub-region.
        Returns (region_name, selected_sub_regions, targets[(sub_region_name, host)]).
        """
        env_cfg = self._config.environments.get(environment)
        if env_cfg is None:
            raise ValueError(f"Unknown environment: {environment}")

        if name in env_cfg.regions:
            sub_map = env_cfg.regions[name].sub_regions
            available = sorted(sub_map.keys())
            chosen = sorted({sr for sr in (sub_regions or []) if sr})
            if chosen:
                invalid = [sr for sr in chosen if sr not in sub_map]
                if invalid:
                    raise ValueError(f"Unknown sub-region(s) in {name}: {', '.join(invalid)}")
            else:
                chosen = available
            targets: List[Tuple[str, HostConfig]] = []
            for sub_name in chosen:
                for host in sub_map[sub_name].hosts:
                    targets.append((sub_name, host))
            if not targets:
                raise ValueError(f"No hosts configured in selected sub-regions for region {name}")
            return name, chosen, targets

        for region_name, region_cfg in env_cfg.regions.items():
            if name in region_cfg.sub_regions:
                targets = [(name, host) for host in region_cfg.sub_regions[name].hosts]
                if not targets:
                    raise ValueError(f"No hosts configured in sub-region {name}")
                return region_name, [name], targets

        raise ValueError(f"Unknown region/sub-region: {name} in environment {environment}")

    def get_reachable_targets(
        self,
        force_refresh: bool = False,
        environment: str | None = None,
        region: str | None = None,
    ) -> Dict[str, object]:
        LOGGER.debug("Refreshing reachable targets force_refresh=%s", force_refresh, extra={"category": "CAPTURE"})
        now = time.time()
        with self._reachability_lock:
            if environment is None:
                cache_valid = (now - self._reachability_at) < REACHABILITY_TTL_SECONDS
            else:
                env_refresh_at = self._reachability_at_by_env.get(environment, 0.0)
                cache_valid = (now - env_refresh_at) < REACHABILITY_TTL_SECONDS and environment in self._reachable_hosts
            if cache_valid and not force_refresh:
                cache_age = now - (self._reachability_at if environment is None else self._reachability_at_by_env.get(environment, now))
                LOGGER.debug("Using reachability cache age_seconds=%.2f", cache_age, extra={"category": "CAPTURE"})
                reachable_cached = self._reachable_hosts if environment is None else self._reachable_hosts.get(environment, {})
                unreachable_cached = self._unreachable_hosts if environment is None else self._unreachable_hosts.get(environment, {})
                if region:
                    reachable_cached = {region: reachable_cached.get(region, {})} if isinstance(reachable_cached, dict) else {}
                    unreachable_cached = {region: unreachable_cached.get(region, {})} if isinstance(unreachable_cached, dict) else {}
                return {
                    "refreshed_at": self._reachability_at if environment is None else self._reachability_at_by_env.get(environment),
                    "reachable": reachable_cached,
                    "unreachable": unreachable_cached,
                }

        reachable: Dict[str, Dict[str, Dict[str, List[HostConfig]]]] = {}
        unreachable: Dict[str, Dict[str, Dict[str, Dict[str, str]]]] = {}

        def probe(environment_name: str, region_name: str, sub_region_name: str, host: HostConfig) -> tuple[str, str, str, str, bool, str]:
            try:
                for iface in host.interfaces:
                    self._preflight_rpcap(host, iface)
                return environment_name, region_name, sub_region_name, host.id, True, ""
            except Exception as exc:
                return environment_name, region_name, sub_region_name, host.id, False, str(exc)

        futures = []
        with ThreadPoolExecutor(max_workers=REACHABILITY_MAX_WORKERS) as ex:
            if environment is None:
                env_items = self._config.environments.items()
            else:
                env_cfg = self._config.environments.get(environment)
                if env_cfg is None:
                    raise ValueError(f"Unknown environment: {environment}")
                env_items = [(environment, env_cfg)]
            for environment_name, environment_cfg in env_items:
                if region is None:
                    region_items = environment_cfg.regions.items()
                else:
                    region_cfg = environment_cfg.regions.get(region)
                    if region_cfg is None:
                        raise ValueError(f"Unknown region {region} in environment {environment_name}")
                    region_items = [(region, region_cfg)]
                for region_name, region_cfg in region_items:
                    for sub_region_name, sub_region_cfg in region_cfg.sub_regions.items():
                        for host in sub_region_cfg.hosts:
                            futures.append(ex.submit(probe, environment_name, region_name, sub_region_name, host))

            for fut in as_completed(futures):
                environment_name, region_name, sub_region_name, host_id, ok, reason = fut.result()
                if ok:
                    host_cfg = next(
                        h
                        for h in self._config.environments[environment_name].regions[region_name].sub_regions[sub_region_name].hosts
                        if h.id == host_id
                    )
                    reachable.setdefault(environment_name, {}).setdefault(region_name, {}).setdefault(sub_region_name, []).append(host_cfg)
                else:
                    unreachable.setdefault(environment_name, {}).setdefault(region_name, {}).setdefault(sub_region_name, {})[host_id] = reason
                    LOGGER.warning(
                        "Host unreachable environment=%s region=%s sub_region=%s host=%s reason=%s",
                        environment_name,
                        region_name,
                        sub_region_name,
                        host_id,
                        reason,
                        extra={"category": "CAPTURE"},
                    )

        for environment_name in reachable:
            for region_name in reachable[environment_name]:
                for sub_region_name in reachable[environment_name][region_name]:
                    reachable[environment_name][region_name][sub_region_name].sort(key=lambda h: h.id)

        with self._reachability_lock:
            refreshed_at = time.time()
            if environment is None:
                self._reachability_at = refreshed_at
                self._reachable_hosts = reachable
                self._unreachable_hosts = unreachable
                self._reachability_at_by_env = {env: refreshed_at for env in self._config.environments.keys()}
            else:
                if region is None:
                    self._reachable_hosts[environment] = reachable.get(environment, {})
                    self._unreachable_hosts[environment] = unreachable.get(environment, {})
                else:
                    self._reachable_hosts.setdefault(environment, {})[region] = reachable.get(environment, {}).get(region, {})
                    self._unreachable_hosts.setdefault(environment, {})[region] = unreachable.get(environment, {}).get(region, {})
                self._reachability_at_by_env[environment] = refreshed_at
            reachable_out = self._reachable_hosts if environment is None else self._reachable_hosts.get(environment, {})
            unreachable_out = self._unreachable_hosts if environment is None else self._unreachable_hosts.get(environment, {})
            if region:
                reachable_out = {region: reachable_out.get(region, {})} if isinstance(reachable_out, dict) else {}
                unreachable_out = {region: unreachable_out.get(region, {})} if isinstance(unreachable_out, dict) else {}
            LOGGER.info(
                "Reachability refresh done reachable_regions=%s unreachable_regions=%s",
                len(reachable_out) if isinstance(reachable_out, dict) else 0,
                len(unreachable_out) if isinstance(unreachable_out, dict) else 0,
                extra={"category": "CAPTURE"},
            )
            return {
                "refreshed_at": refreshed_at,
                "reachable": reachable_out,
                "unreachable": unreachable_out,
            }

    def start_capture(
        self,
        environment: str,
        region: str,
        sub_regions: list[str] | None,
        bpf_filter: str,
        host_ids: list[str] | None = None,
        output_dir_name: str | None = None,
        resume_session_id: str | None = None,
        timeout_minutes: int | None = None,
        storage_location: str | None = None,
        s3_spool_dir: str | None = None,
    ) -> CaptureSession:
        request_cid = short_uuid()
        LOGGER.info(
            "Start capture requested environment=%s region=%s sub_regions=%s host_ids=%s filter=%s output_dir_name=%s resume_session_id=%s storage_location=%s s3_spool_dir=%s",
            environment,
            region,
            sub_regions or [],
            host_ids or [],
            bpf_filter,
            output_dir_name or "-",
            resume_session_id or "-",
            (storage_location or "").strip() or "-",
            (s3_spool_dir or "").strip() or "-",
            extra={"category": "CAPTURE", "correlation_id": request_cid},
        )
        if timeout_minutes is not None and timeout_minutes <= 0:
            raise ValueError("Timeout must be a positive number of minutes")
        if self._active_session and self._active_session.running:
            raise ValueError("A capture session is already running")

        top_region, selected_sub_regions, all_targets = self._resolve_capture_scope(environment, region, sub_regions)

        bpf_filter = (bpf_filter or "").strip()
        if bpf_filter == "":
            bpf_filter = "udp"

        targets = all_targets
        if host_ids:
            selected_ids = set(host_ids)
            targets = [(sub_region_name, h) for sub_region_name, h in targets if h.id in selected_ids]
            if not targets:
                raise ValueError("No valid selected hosts found in selected sub-regions")

        reach = self.get_reachable_targets(force_refresh=True, environment=environment, region=top_region)
        for sub_region_name, h in targets:
            reachable_in_sub_region: Dict[str, HostConfig] = {
                r.id: r
                for r in (
                    (
                        reach["reachable"].get(top_region, {}).get(sub_region_name, [])
                        if isinstance(reach["reachable"], dict)
                        else []
                    )
                )
            }
            if h.id not in reachable_in_sub_region:
                reason = ""
                if isinstance(reach["unreachable"], dict):
                    reason = (reach["unreachable"].get(top_region, {}).get(sub_region_name, {}) or {}).get(h.id, "")
                msg = f"Host is not reachable via rpcapd: {environment}/{top_region}/{sub_region_name}/{h.id} ({h.address})"
                if reason:
                    msg += f" - {reason}"
                raise ValueError(msg)

        resumed_from: Optional[CaptureSession] = None
        safe_output_dir: Optional[str] = None
        if output_dir_name:
            safe_output_dir = _safe_folder_name(output_dir_name)
            if not safe_output_dir:
                raise ValueError("Invalid output directory name")
        if resume_session_id:
            latest = self._latest_session
            if latest is None or latest.session_id != resume_session_id:
                raise ValueError(f"Cannot resume capture: session_id not found ({resume_session_id})")
            if latest.running:
                raise ValueError("Cannot resume capture: session is already running")
            resumed_from = latest

        if resumed_from is not None:
            session_id = resumed_from.session_id
            base_dir = resumed_from.base_dir
            raw_dir = resumed_from.raw_dir
            uploads_dir = resumed_from.uploads_dir
            decrypted_dir = resumed_from.decrypted_dir
            safe_output_dir = resumed_from.output_dir_name
            raw_dir.mkdir(parents=True, exist_ok=True)
            uploads_dir.mkdir(parents=True, exist_ok=True)
            decrypted_dir.mkdir(parents=True, exist_ok=True)
        else:
            session_id = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            base_dir = self._capture_root
            if safe_output_dir:
                base_dir = base_dir / safe_output_dir
            base_dir = base_dir / session_id
            requested_storage = (storage_location or "").strip().lower()
            if requested_storage not in {"", "local", "s3"}:
                raise ValueError("Invalid capture storage location")
            prefer_s3 = requested_storage == "s3" or (requested_storage == "" and self._s3.enabled and self._s3.configured)
            if prefer_s3:
                if not self._s3.enabled:
                    raise ValueError("S3 storage mode is disabled")
                if not self._s3.configured:
                    raise ValueError("S3 storage is not configured")
                custom_spool_root = (s3_spool_dir or "").strip()
                if custom_spool_root:
                    raw_root = Path(custom_spool_root).expanduser()
                else:
                    raw_root = self._tmp_root / "rtphelper-capture-spool"
                try:
                    raw_root.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    raise ValueError(f"Cannot create S3 spool directory: {raw_root} ({exc})") from exc
                raw_dir = raw_root / session_id / "raw"
            else:
                raw_dir = base_dir / "raw"
            uploads_dir = base_dir / "uploads"
            decrypted_dir = base_dir / "decrypted"
            raw_dir.mkdir(parents=True, exist_ok=True)
            uploads_dir.mkdir(parents=True, exist_ok=True)
            decrypted_dir.mkdir(parents=True, exist_ok=True)

        if resumed_from is not None:
            storage_mode = resumed_from.storage_mode
            storage_notice = resumed_from.storage_notice
        else:
            requested_storage = (storage_location or "").strip().lower()
            if requested_storage == "local":
                storage_mode, storage_notice = "local", None
            elif requested_storage == "s3":
                storage_mode, storage_notice = "s3", None
            else:
                storage_mode, storage_notice = self._session_storage_mode()
        session = CaptureSession(
            session_id=session_id,
            environment=environment,
            region=top_region,
            sub_regions=selected_sub_regions,
            bpf_filter=bpf_filter,
            base_dir=base_dir,
            raw_dir=raw_dir,
            uploads_dir=uploads_dir,
            decrypted_dir=decrypted_dir,
            started_at=resumed_from.started_at if resumed_from is not None else dt.datetime.utcnow(),
            storage_mode=storage_mode,
            storage_notice=storage_notice,
            timeout_minutes=timeout_minutes,
            timeout_at=(dt.datetime.utcnow() + dt.timedelta(minutes=timeout_minutes)) if timeout_minutes else None,
            local_spool_max_bytes=self.local_spool_max_bytes,
            output_dir_name=safe_output_dir,
        )
        if resumed_from is not None:
            session.uploaded_files = dict(resumed_from.uploaded_files)
            session.uploaded_objects = dict(resumed_from.uploaded_objects)
            session.last_sip_pcap = resumed_from.last_sip_pcap
            session.last_call_id = resumed_from.last_call_id
        if session.storage_notice:
            LOGGER.warning(
                "S3 unavailable at capture start session_id=%s notice=%s",
                session.session_id,
                session.storage_notice,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )
        elif session.storage_mode == "s3":
            LOGGER.info(
                "S3 storage enabled session_id=%s bucket=%s prefix=%s",
                session.session_id,
                self._s3.bucket,
                self._s3.prefix or "-",
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )
            self._set_s3_pool_mode(capture_running=True)
            self._set_s3_upload_mode(capture_running=True)
        else:
            LOGGER.info(
                "Local storage selected session_id=%s raw_dir=%s",
                session.session_id,
                session.raw_dir,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )

        for capture_sub_region, host in targets:
            session.host_packet_counts[host.id] = 0
            existing_files = sorted(session.raw_dir.glob(f"{capture_sub_region}-{host.id}-*.pcap"))
            session.host_files[host.id] = list(existing_files)

            # We'll open linktype from the first interface; assume same DLT across host interfaces.
            client = RpcapClient(host.address, port=host.port or self._config.rpcap.default_port)
            client.connect()
            client.auth_null()
            open_info = client.open(host.interfaces[0])
            client.close()

            writer = RollingPcapWriter(
                base_dir=session.raw_dir,
                file_prefix=f"{capture_sub_region}-{host.id}",
                max_bytes=_rolling_pcap_max_bytes(),
                max_seconds=_rolling_pcap_max_seconds(),
                linktype=open_info.linktype,
                snaplen=DEFAULT_SNAPLEN,
            )
            first_file = writer.open_next()
            session.host_files[host.id].append(first_file)

            workers: List[HostCaptureWorker] = []
            for iface in host.interfaces:
                t = threading.Thread(
                    target=self._capture_loop,
                    name=f"rpcap-{host.id}-{iface}",
                    args=(session, host, iface, writer),
                    daemon=True,
                )
                t.start()
                workers.append(HostCaptureWorker(host=host, interface=iface, thread=t))

            session.host_workers[host.id] = workers

        self._active_session = session
        self._latest_session = session
        self._sessions_by_id[session.session_id] = session
        self.sync_session_storage(session, include_running=True, force=True)
        self._start_s3_maintenance(session)
        if session.timeout_at:
            self._start_timeout_watchdog(session)
        LOGGER.info(
            "Capture session started session_id=%s environment=%s region=%s hosts=%s filter=%s resumed=%s timeout_minutes=%s",
            session.session_id,
            session.environment,
            session.region,
            list(session.host_workers.keys()),
            session.bpf_filter,
            bool(resumed_from),
            session.timeout_minutes if session.timeout_minutes else "-",
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )
        return session

    def create_import_session(self, output_dir_name: str | None = None) -> CaptureSession:
        """
        Create a non-running session used to process existing capture files selected by the user.
        The caller is responsible for populating session.host_files (and writing files to session.raw_dir).
        """
        if self._active_session and self._active_session.running:
            raise ValueError("A capture session is already running")

        session_id = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_dir = self._capture_root
        if output_dir_name:
            safe = _safe_folder_name(output_dir_name)
            if not safe:
                raise ValueError("Invalid output directory name")
            base_dir = base_dir / safe
        base_dir = base_dir / session_id
        raw_dir = base_dir / "raw"
        uploads_dir = base_dir / "uploads"
        decrypted_dir = base_dir / "decrypted"
        raw_dir.mkdir(parents=True, exist_ok=True)
        uploads_dir.mkdir(parents=True, exist_ok=True)
        decrypted_dir.mkdir(parents=True, exist_ok=True)

        now = dt.datetime.utcnow()
        # Post-process/import session is always local-only.
        storage_mode, storage_notice = "local", None
        session = CaptureSession(
            session_id=session_id,
            environment="imported",
            region="imported",
            sub_regions=["imported"],
            bpf_filter="imported",
            base_dir=base_dir,
            raw_dir=raw_dir,
            uploads_dir=uploads_dir,
            decrypted_dir=decrypted_dir,
            started_at=now,
            stopped_at=now,
            running=False,
            storage_mode=storage_mode,
            storage_notice=storage_notice,
            source_mode="import_upload",
            raw_dir_managed=True,
        )
        if session.storage_notice:
            LOGGER.warning(
                "S3 unavailable for import session_id=%s notice=%s",
                session.session_id,
                session.storage_notice,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )

        self._active_session = None
        self._latest_session = session
        self._sessions_by_id[session.session_id] = session
        return session

    def create_import_reference_session(
        self,
        media_files: List[Path],
        base_media_dir: Path,
        output_dir_name: str | None = None,
    ) -> CaptureSession:
        """
        Create a non-running session that references existing local media files without copying them.
        Output directories are created under base_media_dir, with no timestamp folder.
        """
        if self._active_session and self._active_session.running:
            raise ValueError("A capture session is already running")
        if not media_files:
            raise ValueError("No media files were provided")

        session_id = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_dir = base_media_dir.expanduser().resolve()
        if output_dir_name:
            safe = _safe_folder_name(output_dir_name)
            if not safe:
                raise ValueError("Invalid output directory name")
            base_dir = base_dir / safe
        uploads_dir = base_dir / "uploads"
        decrypted_dir = base_dir / "decrypted"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        decrypted_dir.mkdir(parents=True, exist_ok=True)

        now = dt.datetime.utcnow()
        session = CaptureSession(
            session_id=session_id,
            environment="imported",
            region="imported",
            sub_regions=["imported"],
            bpf_filter="imported",
            base_dir=base_dir,
            raw_dir=base_media_dir.expanduser().resolve(),
            uploads_dir=uploads_dir,
            decrypted_dir=decrypted_dir,
            started_at=now,
            stopped_at=now,
            running=False,
            storage_mode="local",
            storage_notice=None,
            source_mode="local_reference",
            raw_dir_managed=False,
        )

        host_files: Dict[str, List[Path]] = {}
        for path in media_files:
            host_key = self._host_key_from_capture_filename(path.name)
            host_files.setdefault(host_key, []).append(path)
        for host_id in host_files:
            host_files[host_id] = sorted(host_files[host_id], key=lambda p: p.name)
        session.host_files = host_files
        session.host_packet_counts = {host_id: 0 for host_id in host_files}

        self._active_session = None
        self._latest_session = session
        self._sessions_by_id[session.session_id] = session
        return session

    def stop_capture(self, stop_reason: str = "manual") -> CaptureSession:
        if not self._active_session or not self._active_session.running:
            raise ValueError("No active capture session")
        session = self._active_session

        session.stop_event.set()
        maint = self._maintenance_threads.get(session.session_id)
        if maint and maint.is_alive():
            maint.join(timeout=3)
        self._maintenance_threads.pop(session.session_id, None)
        for workers in session.host_workers.values():
            for worker in workers:
                worker.thread.join(timeout=5)

        # Refresh per-host file lists to include all rotated segments (0001, 0002, ...).
        self._refresh_session_host_files(session)

        session.running = False
        session.stop_reason = stop_reason
        session.stopped_at = dt.datetime.utcnow()
        self._set_s3_pool_mode(capture_running=False)
        self._set_s3_upload_mode(capture_running=False)
        self._enqueue_storage_flush(session, source="stop_capture")
        self._active_session = None
        LOGGER.info(
            "Capture session stopped session_id=%s failed=%s failure_reason=%s stop_reason=%s",
            session.session_id,
            session.failed,
            session.failure_reason or "-",
            session.stop_reason or "-",
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )
        return session

    def _refresh_session_host_files(self, session: CaptureSession) -> None:
        refreshed: Dict[str, List[Path]] = {}
        s3_source_by_host: Dict[str, List[str]] = {}

        # Build a robust view over uploaded raw artifacts:
        # - uploaded_objects values are full S3 keys
        # - uploaded_objects keys are relative paths (e.g. "raw/file.pcap")
        uploaded_s3_keys = [str(v) for v in session.uploaded_objects.values() if str(v).strip()]
        uploaded_refs = uploaded_s3_keys + [str(k) for k in session.uploaded_objects.keys() if str(k).strip()]

        def _raw_name(ref: str) -> str:
            text = str(ref or "").strip()
            if not text:
                return ""
            if "/raw/" in text:
                return text.rsplit("/raw/", 1)[-1].strip()
            if text.startswith("raw/"):
                return text.split("raw/", 1)[-1].strip()
            if text.startswith("raw\\"):
                return text.split("raw\\", 1)[-1].strip()
            return ""

        for host_id in session.host_packet_counts.keys():
            files = sorted(session.raw_dir.glob(f"*-{host_id}-*.pcap"))
            if not files:
                files = sorted(session.raw_dir.glob(f"*-{host_id}-*.pcapng"))
            # Keep placeholders for raw files already uploaded to S3 (may no longer exist locally).
            uploaded_names: List[str] = []
            for ref in uploaded_refs:
                name = _raw_name(ref)
                if not name:
                    continue
                if f"-{host_id}-" not in name:
                    continue
                if not (name.endswith(".pcap") or name.endswith(".pcapng")):
                    continue
                uploaded_names.append(name)
            host_s3_keys = []
            for s3_key in uploaded_s3_keys:
                name = _raw_name(s3_key)
                if not name:
                    continue
                if f"-{host_id}-" not in name:
                    continue
                if not (name.endswith(".pcap") or name.endswith(".pcapng")):
                    continue
                host_s3_keys.append(s3_key)
            if host_s3_keys:
                s3_source_by_host[host_id] = sorted(set(host_s3_keys))
            if uploaded_names:
                existing_names = {p.name for p in files}
                for name in sorted(set(uploaded_names)):
                    if name not in existing_names:
                        files.append(session.raw_dir / name)
            refreshed[host_id] = files
        if refreshed:
            session.host_files = refreshed
        if s3_source_by_host:
            session.s3_source_objects = s3_source_by_host
            # Derive session prefix from first known S3 raw key.
            first_key = next((k for keys in s3_source_by_host.values() for k in keys), "")
            if "/raw/" in first_key:
                session.s3_source_session_prefix = first_key.rsplit("/raw/", 1)[0]

    def latest_session(self) -> Optional[CaptureSession]:
        return self._latest_session

    def session_by_id(self, session_id: str) -> Optional[CaptureSession]:
        return self._sessions_by_id.get(str(session_id or "").strip())

    def refresh_session_media_index(self, session: CaptureSession) -> None:
        self._refresh_session_host_files(session)

    def active_session(self) -> Optional[CaptureSession]:
        return self._active_session

    def session_packet_counts(self, session: CaptureSession) -> Dict[str, int]:
        total = sum(session.host_packet_counts.values())
        counts = dict(session.host_packet_counts)
        counts["total"] = total
        return counts

    def ensure_session_health(self) -> Optional[str]:
        session = self._active_session
        if session is None or not session.running:
            return None
        if session.failed:
            LOGGER.warning(
                "Active session unhealthy session_id=%s reason=%s",
                session.session_id,
                session.failure_reason or "-",
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )
            return session.failure_reason
        if session.storage_mode == "s3":
            try:
                self.sync_session_storage(session, include_running=True, force=False)
                self._enforce_spool_limit(session)
            except Exception as exc:
                self._abort_active_session(session, reason=str(exc), host_id="storage")
                return session.failure_reason
        return None

    def _abort_active_session(self, session: CaptureSession, reason: str, host_id: str) -> None:
        if session.failed:
            return
        session.failed = True
        session.failure_reason = reason
        session.stop_reason = "error"
        session.host_errors[host_id] = reason
        LOGGER.error(
            "Aborting capture session due to failure host=%s reason=%s",
            host_id,
            reason,
            extra={"category": "ERRORS", "correlation_id": session.session_id},
        )
        session.stop_event.set()

    def _preflight_rpcap(self, host: HostConfig, iface: str) -> None:
        client = RpcapClient(host.address, port=host.port or self._config.rpcap.default_port)
        client.connect()
        try:
            client.auth_null()
            client.open(iface)
        finally:
            client.close()

    def _connect_and_start_capture(
        self,
        session: CaptureSession,
        host: HostConfig,
        iface: str,
        client: RpcapClient,
    ) -> None:
        LOGGER.info(
            "Connecting to RPCAP server session_id=%s host=%s iface=%s address=%s port=%s",
            session.session_id,
            host.id,
            iface,
            host.address,
            host.port or self._config.rpcap.default_port,
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )
        client.connect()
        client.auth_null()
        client.open(iface)
        # Many rpcapd implementations expect the filter to be included in STARTCAP.
        client.start_capture(
            snaplen=DEFAULT_SNAPLEN,
            read_timeout_ms=1000,
            promisc=True,
            filter_expr=session.bpf_filter,
        )
        LOGGER.info(
            "Connected to RPCAP server session_id=%s host=%s iface=%s filter=%s",
            session.session_id,
            host.id,
            iface,
            session.bpf_filter,
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )

    def _capture_packets_loop(
        self,
        session: CaptureSession,
        host_id: str,
        writer: RollingPcapWriter,
        client: RpcapClient,
    ) -> None:
        while not session.stop_event.is_set():
            pkt = client.recv_packet()
            if pkt is None:
                continue
            ts_sec, ts_usec, _orig_len, frame = pkt
            frame = normalize_link_layer_frame(writer.linktype, frame)
            writer.write_packet(ts_sec, ts_usec, frame, len(frame))
            session.host_packet_counts[host_id] = session.host_packet_counts.get(host_id, 0) + 1

    def _is_reconnectable_capture_error(self, exc: Exception) -> bool:
        if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
            return True
        msg = str(exc).lower()
        reconnect_tokens = (
            "timed out",
            "timeout",
            "connection reset",
            "broken pipe",
            "connection aborted",
            "connection refused",
            "network is unreachable",
            "host is unreachable",
            "eof",
        )
        return any(token in msg for token in reconnect_tokens)

    def _capture_loop(self, session: CaptureSession, host: HostConfig, iface: str, writer: RollingPcapWriter) -> None:
        host_id = host.id
        reconnect_attempts = 0
        last_reason = ""
        try:
            LOGGER.info(
                "Capture loop start session_id=%s host=%s iface=%s filter=%s",
                session.session_id,
                host.id,
                iface,
                session.bpf_filter,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )
            while not session.stop_event.is_set():
                client = RpcapClient(host.address, port=host.port or self._config.rpcap.default_port)
                try:
                    if reconnect_attempts > 0:
                        LOGGER.info(
                            "Reconnecting to RPCAP server session_id=%s host=%s iface=%s attempt=%s",
                            session.session_id,
                            host.id,
                            iface,
                            reconnect_attempts,
                            extra={"category": "CAPTURE", "correlation_id": session.session_id},
                        )
                    self._connect_and_start_capture(session, host, iface, client)
                    if reconnect_attempts > 0:
                        LOGGER.info(
                            "Reconnected to RPCAP server session_id=%s host=%s iface=%s attempts=%s",
                            session.session_id,
                            host.id,
                            iface,
                            reconnect_attempts,
                            extra={"category": "CAPTURE", "correlation_id": session.session_id},
                        )
                        reconnect_attempts = 0
                    self._capture_packets_loop(session, host_id, writer, client)
                    # capture_packets_loop exits only when stop_event is set.
                    break
                except Exception as exc:
                    if session.stop_event.is_set():
                        break
                    last_reason = str(exc) or exc.__class__.__name__
                    session.host_errors[host_id] = last_reason
                    if not self._is_reconnectable_capture_error(exc):
                        LOGGER.exception(
                            "Capture loop failure session_id=%s host=%s iface=%s",
                            session.session_id,
                            host.id,
                            iface,
                            extra={"category": "ERRORS", "correlation_id": session.session_id},
                        )
                        self._abort_active_session(session, reason=last_reason, host_id=host_id)
                        break
                    reconnect_attempts += 1
                    if RPCAP_RECONNECT_MAX_ATTEMPTS > 0 and reconnect_attempts > RPCAP_RECONNECT_MAX_ATTEMPTS:
                        self._abort_active_session(
                            session,
                            reason=(
                                f"RPCAP reconnect failed host={host_id} attempts={reconnect_attempts - 1} "
                                f"last_error={last_reason}"
                            ),
                            host_id=host_id,
                        )
                        break
                    backoff = min(RPCAP_RECONNECT_MAX_SECONDS, RPCAP_RECONNECT_BASE_SECONDS * (2 ** (reconnect_attempts - 1)))
                    LOGGER.warning(
                        (
                            "RPCAP stream interrupted session_id=%s host=%s iface=%s reason=%s "
                            "reconnect_attempt=%s backoff_s=%.1f"
                        ),
                        session.session_id,
                        host.id,
                        iface,
                        last_reason,
                        reconnect_attempts,
                        backoff,
                        extra={"category": "CAPTURE", "correlation_id": session.session_id},
                    )
                    session.stop_event.wait(backoff)
                finally:
                    try:
                        client.end_capture()
                    except Exception:
                        pass
                    client.close()
        finally:
            try:
                writer.close()
            except Exception:
                pass
            LOGGER.info(
                "Capture loop stop session_id=%s host=%s iface=%s",
                session.session_id,
                host.id,
                iface,
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )

    def _start_timeout_watchdog(self, session: CaptureSession) -> None:
        if not session.timeout_at:
            return
        t = threading.Thread(
            target=self._timeout_watchdog,
            args=(session,),
            name=f"capture-timeout-{session.session_id}",
            daemon=True,
        )
        t.start()

    def _timeout_watchdog(self, session: CaptureSession) -> None:
        if not session.timeout_at:
            return
        while True:
            if session.stop_event.is_set():
                return
            remaining = (session.timeout_at - dt.datetime.utcnow()).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(1.0, max(0.1, remaining)))

        if session.stop_event.is_set():
            return
        if self._active_session is not session or not session.running:
            return
        try:
            self.stop_capture(stop_reason="timeout")
            LOGGER.info(
                "Capture session auto-stopped due to timeout session_id=%s timeout_minutes=%s",
                session.session_id,
                session.timeout_minutes or "-",
                extra={"category": "CAPTURE", "correlation_id": session.session_id},
            )
        except ValueError:
            # Session may have been stopped concurrently.
            return


def _safe_folder_name(name: str) -> str:
    """
    Convert a user-provided folder name into a safe single path segment.
    """
    value = (name or "").strip()
    if not value:
        return ""
    value = value.replace(" ", "_")
    # Only allow a conservative set.
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    value = "".join(ch for ch in value if ch in allowed)
    if value in {"", ".", ".."}:
        return ""
    if len(value) > 64:
        value = value[:64]
    return value
