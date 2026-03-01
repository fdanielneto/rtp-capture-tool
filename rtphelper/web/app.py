from __future__ import annotations

import logging
import os
import asyncio
import json
import io
import datetime as dt
import threading
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import shutil
import shlex
import subprocess
import time
import base64
import tempfile

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from starlette.requests import Request
from starlette.responses import Response

from rtphelper.config_loader import load_config
from rtphelper.env_loader import load_env_file
from rtphelper.logging_setup import LOG_FILE, correlation_context, get_access_logger, setup_logging, short_uuid
from rtphelper.services.capture_service import CaptureService, CaptureSession
from rtphelper.services.decryption_service import DecryptionResult, DecryptionService
from rtphelper.services.media_extract import extract_stream_to_pcap
from rtphelper.services.pcap_tools import merge_pcaps
from rtphelper.services.sip_parser import SdesCryptoMaterial, SipCall, SipMessage, parse_sip_pcap
from rtphelper.services.sip_correlation import (
    correlate_sip_call,
    group_related_calls,
    merge_calls_by_group,
    build_correlation_context,
    build_tshark_filters,
    detect_rtpengine_ip_from_pcap,
    CorrelationContext,
)
from rtphelper.services.correlation_progress import emit_progress
from rtphelper.services.correlation_worker_client import run_correlation_job_via_subprocess
from rtphelper.services.stream_matcher import (
    match_streams,
)
from rtphelper.services.job_orchestrator import CorrelationJobWorker, JobOrchestrator
from rtphelper.utils import ensure_macos_arm

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import PcapReader

LOGGER = logging.getLogger(__name__)
ACCESS_LOGGER = get_access_logger()
_LOGS_POLL_RATE_LIMIT_RPS = max(1, int(os.environ.get("RTPHELPER_LOGS_POLL_RATE_LIMIT_RPS", "6")))
_LOGS_POLL_CLIENT_WINDOW_S = 1.0
_logs_poll_rate_lock = threading.Lock()
_logs_poll_client_hits: Dict[str, List[float]] = {}
CORRELATION_HEARTBEAT_SECONDS = max(
    5.0, float(os.environ.get("RTPHELPER_CORRELATION_HEARTBEAT_SECONDS", "10") or "10")
)
MAX_PARALLEL_FILTER_WORKERS = max(
    1, int(os.environ.get("RTPHELPER_MAX_PARALLEL_FILTER_WORKERS", "10") or "10")
)

BASE_DIR = Path(__file__).resolve().parents[2]
ENV_PATH = Path(os.environ.get("RTPHELPER_ENV_FILE", BASE_DIR / "config" / "runtime.env"))
load_env_file(ENV_PATH)
CONFIG_PATH = Path(os.environ.get("RTPHELPER_CONFIG", BASE_DIR / "config" / "hosts.yaml"))
DEFAULT_CAPTURE_ROOT = Path.home() / "Downloads"

setup_logging()
ensure_macos_arm()

CONFIG = load_config(CONFIG_PATH)
_capture_root_env = os.environ.get("RTPHELPER_CAPTURE_ROOT", "").strip()
if _capture_root_env:
    CAPTURE_ROOT = Path(_capture_root_env).expanduser()
else:
    CAPTURE_ROOT = (CONFIG.settings.default_capture_root or DEFAULT_CAPTURE_ROOT).expanduser()
CAPTURE_SERVICE = CaptureService(CONFIG, CAPTURE_ROOT)
DECRYPTION_SERVICE = DecryptionService()
JOB_DB_PATH = Path(os.environ.get("RTPHELPER_JOB_DB_PATH", str(BASE_DIR / "logs" / "jobs.sqlite3"))).expanduser()
JOB_ORCHESTRATOR = JobOrchestrator(
    db_path=JOB_DB_PATH,
    max_queue_size=int(os.environ.get("RTPHELPER_JOB_QUEUE_SIZE", "256")),
)
CORRELATION_JOB_WORKER: CorrelationJobWorker | None = None
EMBEDDED_WORKER_ENABLED = os.environ.get("RTPHELPER_EMBEDDED_WORKER", "1").strip().lower() not in {"0", "false", "no"}
CORRELATION_WORKER_MODE = os.environ.get("RTPHELPER_CORRELATION_WORKER_MODE", "subprocess").strip().lower() or "subprocess"


class LiveCorrelationLog(list):
    """
    Correlation log collector that also emits each line immediately to app logs,
    so the UI can display progress while correlation is running.
    """

    def __init__(self, correlation_id: str) -> None:
        super().__init__()
        self._correlation_id = correlation_id

    def append(self, item) -> None:  # type: ignore[override]
        text = str(item)
        super().append(text)
        upper = text.upper()
        level = "info"
        if upper.startswith("ERROR"):
            level = "error"
            LOGGER.error(text, extra={"category": "RTP_SEARCH", "correlation_id": self._correlation_id})
        elif upper.startswith("WARN"):
            level = "warn"
            LOGGER.warning(text, extra={"category": "RTP_SEARCH", "correlation_id": self._correlation_id})
        else:
            LOGGER.info(text, extra={"category": "RTP_SEARCH", "correlation_id": self._correlation_id})
        emit_progress(text, step="correlation", level=level)


def _run_correlation_job_subprocess(payload: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    job_id = str(payload.get("_job_id", "")).strip()

    def _should_cancel() -> bool:
        return bool(job_id) and JOB_ORCHESTRATOR.is_cancel_requested(job_id)

    if progress_callback is None:
        return run_correlation_job_via_subprocess(payload, should_cancel=_should_cancel)
    return run_correlation_job_via_subprocess(
        payload,
        on_progress=progress_callback,
        should_cancel=_should_cancel,
    )

app = FastAPI(title="RTP Remote Capture Decryptor")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "rtphelper" / "web" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "rtphelper" / "web" / "templates"))


@app.on_event("startup")
async def on_startup() -> None:
    global CORRELATION_JOB_WORKER
    if EMBEDDED_WORKER_ENABLED:
        handler = _run_correlation_job_payload
        if CORRELATION_WORKER_MODE == "subprocess":
            handler = _run_correlation_job_subprocess
        CORRELATION_JOB_WORKER = CorrelationJobWorker(JOB_ORCHESTRATOR, handler)
        CORRELATION_JOB_WORKER.start()
        LOGGER.info(
            "Embedded correlation worker enabled mode=%s",
            CORRELATION_WORKER_MODE,
            extra={"category": "CONFIG"},
        )
    else:
        CORRELATION_JOB_WORKER = None
        LOGGER.info("Embedded correlation worker disabled", extra={"category": "CONFIG"})
    LOGGER.info(
        "Application startup base_dir=%s config=%s capture_root=%s jobs_db=%s log_level=%s",
        BASE_DIR,
        CONFIG_PATH,
        CAPTURE_ROOT,
        JOB_DB_PATH,
        os.environ.get("RTPHELPER_LOG_LEVEL", "INFO").upper(),
        extra={"category": "CONFIG"},
    )


@app.on_event("shutdown")
async def on_shutdown() -> None:
    if CORRELATION_JOB_WORKER is not None:
        CORRELATION_JOB_WORKER.stop()
    CAPTURE_SERVICE.shutdown()
    LOGGER.info("Application shutdown", extra={"category": "CONFIG"})


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    request_cid = request.headers.get("X-Correlation-Id") or short_uuid()
    start_ts = time.perf_counter()
    with correlation_context(request_cid):
        try:
            response: Response = await call_next(request)
        except Exception:
            elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
            ACCESS_LOGGER.warning(
                "HTTP request failed method=%s path=%s client=%s duration_ms=%s",
                request.method,
                request.url.path,
                request.client.host if request.client else "-",
                elapsed_ms,
            )
            LOGGER.exception("HTTP request failed method=%s path=%s", request.method, request.url.path, extra={"category": "ERRORS"})
            raise
        elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
        ACCESS_LOGGER.info(
            "HTTP %s %s status=%s duration_ms=%s client=%s",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            request.client.host if request.client else "-",
        )
        response.headers["X-Correlation-Id"] = request_cid
        return response


def _enforce_logs_poll_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "-"
    now = time.monotonic()
    with _logs_poll_rate_lock:
        hits = _logs_poll_client_hits.get(client, [])
        min_ts = now - _LOGS_POLL_CLIENT_WINDOW_S
        hits = [ts for ts in hits if ts >= min_ts]
        if len(hits) >= _LOGS_POLL_RATE_LIMIT_RPS:
            _logs_poll_client_hits[client] = hits
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded for /api/logs/poll ({_LOGS_POLL_RATE_LIMIT_RPS} req/s per client)",
            )
        hits.append(now)
        _logs_poll_client_hits[client] = hits


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    LOGGER.warning(
        "HTTP exception method=%s path=%s status=%s detail=%s",
        request.method,
        request.url.path,
        exc.status_code,
        exc.detail,
        extra={"category": "ERRORS"},
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    LOGGER.exception(
        "Unhandled exception method=%s path=%s",
        request.method,
        request.url.path,
        extra={"category": "ERRORS"},
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    LOGGER.debug("Rendering index page", extra={"category": "PERF"})
    configured_environments = CAPTURE_SERVICE.list_environments()
    if not configured_environments:
        raise HTTPException(
            status_code=500,
            detail="No environments configured. Please verify config/hosts.yaml",
        )
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "environments": configured_environments,
            "log_level": os.environ.get("RTPHELPER_LOG_LEVEL", "INFO").upper(),
            "capture_root": str(CAPTURE_ROOT),
            "s3_enabled": CAPTURE_SERVICE._s3.enabled,  # type: ignore[attr-defined]
            "s3_configured": CAPTURE_SERVICE._s3.configured,  # type: ignore[attr-defined]
            "s3_spool_default": str(Path(os.environ.get("TMPDIR") or tempfile.gettempdir()).expanduser() / "rtphelper-capture-spool"),
        },
    )

@app.get("/api/targets")
def targets(environment: str = Query("QA"), region: str | None = Query(None), refresh: bool = Query(False)) -> Dict[str, Any]:
    LOGGER.info("API targets refresh requested environment=%s region=%s refresh=%s", environment, region or "-", refresh, extra={"category": "CAPTURE"})
    configured_environments = CAPTURE_SERVICE.list_environments()
    if environment not in configured_environments:
        raise HTTPException(status_code=400, detail=f"Unknown environment: {environment}")
    configured_regions = CAPTURE_SERVICE.list_regions(environment)
    configured_sub_regions = {
        r: CAPTURE_SERVICE.list_sub_regions(environment, r)
        for r in configured_regions
    }
    if not configured_regions:
        # Empty environment (e.g., PRD/STG not provisioned yet) is valid.
        return {
            "refreshed_at": None,
            "selected_environment": environment,
            "selected_region": region,
            "configured_environments": configured_environments,
            "configured_regions": [],
            "configured_sub_regions": {},
            "reachable": {},
            "unreachable": {},
        }
    data = CAPTURE_SERVICE.get_reachable_targets(force_refresh=refresh, environment=environment, region=region)

    reachable: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    if isinstance(data.get("reachable"), dict):
        for region, sub_regions in data["reachable"].items():
            reachable[region] = {}
            for sub_region, hosts in sub_regions.items():
                reachable[region][sub_region] = [
                    {
                        "id": h.id,
                        "address": h.address,
                        "description": h.description,
                        "sub_region": sub_region,
                        "interfaces": h.interfaces,
                        "port": h.port,
                    }
                    for h in hosts
                ]

    unreachable = data.get("unreachable") if isinstance(data.get("unreachable"), dict) else {}
    return {
        "refreshed_at": data.get("refreshed_at"),
        "selected_environment": environment,
        "selected_region": region,
        "configured_environments": configured_environments,
        "configured_regions": configured_regions,
        "configured_sub_regions": configured_sub_regions,
        "reachable": reachable,
        "unreachable": unreachable,
    }


@app.get("/api/config/scope")
def config_scope(environment: str = Query("QA")) -> Dict[str, Any]:
    configured_environments = CAPTURE_SERVICE.list_environments()
    if environment not in configured_environments:
        raise HTTPException(status_code=400, detail=f"Unknown environment: {environment}")
    configured_regions = CAPTURE_SERVICE.list_regions(environment)
    configured_sub_regions = {
        region: CAPTURE_SERVICE.list_sub_regions(environment, region)
        for region in configured_regions
    }
    return {
        "selected_environment": environment,
        "configured_environments": configured_environments,
        "configured_regions": configured_regions,
        "configured_sub_regions": configured_sub_regions,
    }


@app.post("/api/logs/poll")
def poll_logs(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _enforce_logs_poll_rate_limit(request)
    offsets_raw = payload.get("offsets", {})
    offsets: Dict[str, int] = {}
    if isinstance(offsets_raw, dict):
        for k, v in offsets_raw.items():
            try:
                offsets[str(k)] = max(0, int(v))
            except Exception:
                continue

    log_files = _project_log_files()
    files_payload: List[Dict[str, Any]] = []
    for path in log_files:
        abs_path = path.resolve()
        try:
            rel = str(abs_path.relative_to(BASE_DIR))
        except ValueError:
            rel = str(path)
        size = abs_path.stat().st_size
        prev = offsets.get(rel, 0)
        if prev > size:
            prev = 0
        text = ""
        if size > prev:
            with abs_path.open("rb") as fh:
                fh.seek(prev)
                text = fh.read().decode("utf-8", errors="replace")
        files_payload.append(
            {
                "name": rel,
                "size": size,
                "offset_start": prev,
                "text": text,
            }
        )
    return {"files": files_payload}


@app.get("/api/logs/stream")
async def stream_logs(request: Request) -> StreamingResponse:
    offsets: Dict[str, int] = {}
    for path in _project_log_files():
        abs_path = path.resolve()
        try:
            rel = str(abs_path.relative_to(BASE_DIR))
        except ValueError:
            rel = str(path)
        try:
            offsets[rel] = abs_path.stat().st_size
        except Exception:
            offsets[rel] = 0

    async def event_iter():
        keepalive_ticks = 0
        while True:
            if await request.is_disconnected():
                break
            files_payload: List[Dict[str, Any]] = []
            for path in _project_log_files():
                abs_path = path.resolve()
                try:
                    rel = str(abs_path.relative_to(BASE_DIR))
                except ValueError:
                    rel = str(path)
                try:
                    size = abs_path.stat().st_size
                except Exception:
                    size = 0
                prev = offsets.get(rel, 0)
                if prev > size:
                    prev = 0
                text = ""
                if size > prev:
                    try:
                        with abs_path.open("rb") as fh:
                            fh.seek(prev)
                            text = fh.read().decode("utf-8", errors="replace")
                    except Exception:
                        text = ""
                offsets[rel] = size
                if text:
                    files_payload.append(
                        {
                            "name": rel,
                            "size": size,
                            "offset_start": prev,
                            "text": text,
                        }
                    )

            if files_payload:
                keepalive_ticks = 0
                yield f"data: {json.dumps({'files': files_payload})}\n\n"
            else:
                keepalive_ticks += 1
                if keepalive_ticks >= 20:
                    keepalive_ticks = 0
                    yield ": keep-alive\n\n"

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/capture/start")
def start_capture(payload: Dict[str, Any]) -> Dict[str, Any]:
    environment = str(payload.get("environment", "QA")).strip().upper()
    region = str(payload.get("region", "")).strip()
    sub_regions_raw = payload.get("sub_regions", None)
    sub_regions: list[str] | None = None
    if isinstance(sub_regions_raw, list):
        sub_regions = [str(v).strip() for v in sub_regions_raw if str(v).strip()]
    host_ids_raw = payload.get("host_ids", None)
    host_ids: list[str] | None = None
    if isinstance(host_ids_raw, list):
        host_ids = [str(v).strip() for v in host_ids_raw if str(v).strip()]
    bpf_filter = str(payload.get("filter", "")).strip()
    output_dir_name = str(payload.get("output_dir_name", "")).strip()
    storage_location = str(payload.get("storage_location", "")).strip().lower()
    s3_spool_dir = str(payload.get("s3_spool_dir", "")).strip()
    resume_session_id = str(payload.get("resume_session_id", "")).strip()
    timeout_minutes_raw = payload.get("timeout_minutes")
    timeout_minutes: int | None = None
    if timeout_minutes_raw not in (None, ""):
        try:
            timeout_minutes = int(timeout_minutes_raw)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Timeout must be an integer number of minutes") from exc
        if timeout_minutes <= 0:
            raise HTTPException(status_code=400, detail="Timeout must be greater than zero")
    if not region:
        raise HTTPException(status_code=400, detail="Region is required")

    try:
        LOGGER.info(
            "API start capture environment=%s region=%s sub_regions=%s host_ids=%s filter=%s output_dir_name=%s resume_session_id=%s timeout_minutes=%s storage_location=%s s3_spool_dir=%s",
            environment,
            region,
            sub_regions or [],
            host_ids or [],
            bpf_filter or "udp",
            output_dir_name or "-",
            resume_session_id or "-",
            timeout_minutes if timeout_minutes else "-",
            storage_location or "-",
            s3_spool_dir or "-",
            extra={"category": "CAPTURE"},
        )
        session = CAPTURE_SERVICE.start_capture(
            environment=environment,
            region=region,
            sub_regions=sub_regions,
            bpf_filter=bpf_filter,
            host_ids=host_ids,
            output_dir_name=output_dir_name or None,
            resume_session_id=resume_session_id or None,
            timeout_minutes=timeout_minutes,
            storage_location=storage_location or None,
            s3_spool_dir=s3_spool_dir or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "session_id": session.session_id,
        "environment": session.environment,
        "region": session.region,
        "sub_regions": session.sub_regions,
        "filter": session.bpf_filter,
        "timeout_minutes": session.timeout_minutes,
        "timeout_at": session.timeout_at.isoformat() if session.timeout_at else None,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "hosts": list(session.host_workers.keys()),
    }


@app.post("/api/fs/pick-directory")
def pick_directory(payload: Dict[str, Any]) -> Dict[str, Any]:
    initial_path = str(payload.get("initial_path", "")).strip()
    script_lines = ['set chosenFolder to choose folder with prompt "Select local tmp directory for S3 flush"']
    if initial_path:
        initial = Path(initial_path).expanduser()
        if initial.exists() and initial.is_dir():
            safe_initial = str(initial).replace("\\", "\\\\").replace('"', '\\"')
            script_lines = [
                f'set defaultFolder to POSIX file "{safe_initial}"',
                'set chosenFolder to choose folder with prompt "Select local tmp directory for S3 flush" default location defaultFolder',
            ]
    script_lines.append("POSIX path of chosenFolder")
    script = "\n".join(script_lines)
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        err_text = (exc.stderr or exc.stdout or "").strip().lower()
        if "user canceled" in err_text or "cancel" in err_text:
            raise HTTPException(status_code=400, detail="Directory selection cancelled") from exc
        raise HTTPException(status_code=500, detail="Failed to open directory picker") from exc

    selected = (result.stdout or "").strip()
    if not selected:
        raise HTTPException(status_code=400, detail="Directory selection cancelled")
    return {"path": selected}


@app.post("/api/capture/stop")
def stop_capture() -> Dict[str, Any]:
    try:
        session = CAPTURE_SERVICE.stop_capture()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    LOGGER.info("API stop capture session_id=%s", session.session_id, extra={"category": "CAPTURE", "correlation_id": session.session_id})
    return {
        "session_id": session.session_id,
        "running": session.running,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "raw_files": _raw_file_links(session),
        "raw_dir": CAPTURE_SERVICE.storage_target_hint(session),
    }


@app.post("/api/capture/stop-safe")
def stop_capture_safe() -> Dict[str, Any]:
    """
    Idempotent stop endpoint for browser unload/navigation paths.
    Always returns 200 and attempts to stop any active capture.
    """
    session = CAPTURE_SERVICE.active_session()
    if session and session.running:
        session = CAPTURE_SERVICE.stop_capture()
        LOGGER.info(
            "API safe stop capture session_id=%s",
            session.session_id,
            extra={"category": "CAPTURE", "correlation_id": session.session_id},
        )
    else:
        session = CAPTURE_SERVICE.latest_session()

    if session is None:
        return {
            "stopped": False,
            "running": False,
            "session_id": None,
            "storage_mode": "local",
            "storage_notice": None,
            "storage_target": None,
            "storage_flush": {"state": "idle", "pending_files": 0, "attempts": 0, "enqueued_at": None, "started_at": None, "finished_at": None, "error": None},
            "raw_files": {},
            "raw_dir": None,
        }

    return {
        "stopped": True,
        "running": session.running,
        "session_id": session.session_id,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "raw_files": _raw_file_links(session),
        "raw_dir": CAPTURE_SERVICE.storage_target_hint(session),
    }


@app.post("/api/storage/flush/stop")
def stop_storage_flush(payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = payload or {}
    session_id = str(payload.get("session_id", "")).strip()
    try:
        flush = CAPTURE_SERVICE.storage_flush_pause(session_id or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    target_id = session_id or (CAPTURE_SERVICE.latest_session().session_id if CAPTURE_SERVICE.latest_session() else "-")
    target_session = CAPTURE_SERVICE.session_by_id(target_id) if target_id and target_id != "-" else CAPTURE_SERVICE.latest_session()
    local_tmp_dir = str(target_session.raw_dir) if target_session is not None else str(flush.get("tmp_root") or "")
    LOGGER.warning(
        "S3 flush paused by user session_id=%s pending_files=%s",
        target_id,
        int(flush.get("pending_files") or 0),
        extra={"category": "FILES", "correlation_id": target_id},
    )
    return {"session_id": target_id, "storage_flush": flush, "local_tmp_dir": local_tmp_dir}


@app.post("/api/storage/flush/resume")
def resume_storage_flush(payload: Dict[str, Any]) -> Dict[str, Any]:
    session_id = str(payload.get("session_id", "")).strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    try:
        flush = CAPTURE_SERVICE.storage_flush_resume(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    LOGGER.info(
        "S3 flush resumed by user session_id=%s pending_files=%s",
        session_id,
        int(flush.get("pending_files") or 0),
        extra={"category": "FILES", "correlation_id": session_id},
    )
    return {"session_id": session_id, "storage_flush": flush}


@app.post("/api/capture/import")
async def import_capture(
    output_dir_name: str = Form(""),
    media_files: List[UploadFile] = File(...),
) -> Dict[str, Any]:
    LOGGER.info("API import capture requested output_dir_name=%s files_received=%s", output_dir_name or "-", len(media_files), extra={"category": "FILES"})
    if not media_files:
        raise HTTPException(status_code=400, detail="No media files received")

    try:
        session = CAPTURE_SERVICE.create_import_session(output_dir_name=output_dir_name.strip() or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    host_files: Dict[str, List[Path]] = {}

    for upload in media_files:
        if not upload.filename:
            continue
        name = Path(str(upload.filename)).name  # strip any client-side path
        if not (name.endswith(".pcap") or name.endswith(".pcapng")):
            continue

        # De-dup in case of collisions (same basename from multiple subfolders).
        target = session.raw_dir / name
        if target.exists():
            stem = target.stem
            suffix = target.suffix
            i = 1
            while True:
                cand = session.raw_dir / f"{stem}__{i}{suffix}"
                if not cand.exists():
                    target = cand
                    break
                i += 1

        content = await upload.read()
        target.write_bytes(content)

        host_key = _host_key_from_capture_filename(target.name)
        host_files.setdefault(host_key, []).append(target)

    if not host_files:
        raise HTTPException(status_code=400, detail="No .pcap/.pcapng files were found in the selected directory")

    # Sort per host for stable session display/processing.
    for host_id in host_files:
        host_files[host_id] = sorted(host_files[host_id], key=lambda p: p.name)

    session.host_files = host_files
    session.host_packet_counts = {host_id: 0 for host_id in host_files}
    # Correlation should not trigger RTP capture sync to S3.
    # S3 upload is handled in parallel by capture storage maintenance.

    return {
        "session_id": session.session_id,
        "running": session.running,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "raw_files": _raw_file_links(session),
        "raw_dir": CAPTURE_SERVICE.storage_target_hint(session),
    }


@app.post("/api/capture/import-local")
def import_capture_local(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_dir_name = str(payload.get("output_dir_name", "")).strip() or None
    directory_raw = str(payload.get("directory", "")).strip()
    if not directory_raw:
        raise HTTPException(status_code=400, detail="directory is required")
    base = Path(directory_raw).expanduser().resolve()
    if not base.exists() or not base.is_dir():
        raise HTTPException(status_code=400, detail="Selected directory does not exist")
    media_files = sorted(
        list(base.rglob("*.pcap")) + list(base.rglob("*.pcapng")),
        key=lambda p: str(p),
    )
    if not media_files:
        raise HTTPException(status_code=400, detail="No .pcap/.pcapng files were found in selected directory")

    try:
        session = CAPTURE_SERVICE.create_import_reference_session(
            media_files=media_files,
            base_media_dir=base,
            output_dir_name=output_dir_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    LOGGER.info(
        "API local media reference import completed session_id=%s files=%s base_media_dir=%s",
        session.session_id,
        len(media_files),
        base,
        extra={"category": "FILES", "correlation_id": session.session_id},
    )
    return {
        "session_id": session.session_id,
        "running": session.running,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "raw_files": _raw_file_links(session),
        "raw_dir": str(base),
    }


@app.get("/api/s3/sessions")
def list_s3_sessions() -> Dict[str, Any]:
    if not CAPTURE_SERVICE._s3.configured:  # type: ignore[attr-defined]
        raise HTTPException(status_code=400, detail="S3 is not configured")
    try:
        max_keys = int(os.environ.get("RTPHELPER_S3_LIST_MAX_KEYS", "5000"))
        sessions = CAPTURE_SERVICE._s3.list_capture_sessions(max_keys=max_keys)  # type: ignore[attr-defined]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not list S3 sessions: {exc}") from exc
    return {
        "bucket": CAPTURE_SERVICE._s3.bucket,  # type: ignore[attr-defined]
        "prefix": CAPTURE_SERVICE._s3.prefix,  # type: ignore[attr-defined]
        "sessions": sessions,
    }


@app.post("/api/s3/import-session")
def import_s3_session(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not CAPTURE_SERVICE._s3.configured:  # type: ignore[attr-defined]
        raise HTTPException(status_code=400, detail="S3 is not configured")
    session_prefix = str(payload.get("session_prefix", "")).strip()
    if not session_prefix:
        raise HTTPException(status_code=400, detail="session_prefix is required")
    output_dir_name = str(payload.get("output_dir_name", "")).strip()
    try:
        session = CAPTURE_SERVICE.create_import_session(output_dir_name=output_dir_name or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        objects = CAPTURE_SERVICE._s3.list_session_raw_objects(session_prefix)  # type: ignore[attr-defined]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not list objects for selected S3 session: {exc}") from exc
    if not objects:
        raise HTTPException(status_code=404, detail="No raw pcap files found under selected S3 session")

    host_keys: Dict[str, List[str]] = {}
    for obj in objects:
        key = str(obj.get("key") or "")
        if not key:
            continue
        name = Path(key).name
        host_key = _host_key_from_capture_filename(name)
        host_keys.setdefault(host_key, []).append(key)

    if not host_keys:
        raise HTTPException(status_code=404, detail="Selected S3 session did not contain importable pcap files")
    for host_id in host_keys:
        host_keys[host_id] = sorted(host_keys[host_id])

    session.host_files = {}
    session.s3_source_objects = host_keys
    session.s3_source_session_prefix = session_prefix
    session.host_packet_counts = {host_id: 0 for host_id in host_keys}
    LOGGER.info(
        "API S3 import reference completed session_id=%s source_prefix=%s files=%s hosts=%s",
        session.session_id,
        session_prefix,
        sum(len(v) for v in host_keys.values()),
        len(host_keys),
        extra={"category": "FILES", "correlation_id": session.session_id},
    )
    source_raw = session_prefix if session_prefix.endswith("/raw") else f"{session_prefix}/raw"
    return {
        "session_id": session.session_id,
        "running": session.running,
        "storage_mode": "s3",
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE._s3.format_location(source_raw),  # type: ignore[attr-defined]
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "raw_files": _raw_file_links(session),
        "raw_dir": CAPTURE_SERVICE._s3.format_location(source_raw),  # type: ignore[attr-defined]
    }


@app.get("/api/capture/status")
def capture_status() -> Dict[str, Any]:
    CAPTURE_SERVICE.ensure_session_health()
    session = CAPTURE_SERVICE.active_session() or CAPTURE_SERVICE.latest_session()
    if session is None:
        return {
            "running": False,
            "message": "No capture session started",
        }

    counts = CAPTURE_SERVICE.session_packet_counts(session)
    LOGGER.debug(
        "API capture status session_id=%s running=%s failed=%s counts=%s",
        session.session_id,
        session.running,
        session.failed,
        counts,
        extra={"category": "CAPTURE", "correlation_id": session.session_id},
    )
    return {
        "running": session.running,
        "session_id": session.session_id,
        "environment": session.environment,
        "region": session.region,
        "sub_regions": session.sub_regions,
        "filter": session.bpf_filter,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "storage_flush": CAPTURE_SERVICE.storage_flush_status(session),
        "failed": session.failed,
        "failure_reason": session.failure_reason,
        "stop_reason": session.stop_reason,
        "timeout_minutes": session.timeout_minutes,
        "timeout_at": session.timeout_at.isoformat() if session.timeout_at else None,
        "host_errors": session.host_errors,
        "packet_counts": counts,
        "raw_files": _raw_file_links(session),
        "raw_dir": CAPTURE_SERVICE.storage_target_hint(session),
    }


@app.get("/api/health")
def health() -> Dict[str, Any]:
    session = CAPTURE_SERVICE.active_session() or CAPTURE_SERVICE.latest_session()
    status_value = "ok"
    if session and session.failed:
        status_value = "degraded"
    LOGGER.debug("Health check status=%s", status_value, extra={"category": "PERF"})
    return {
        "status": status_value,
        "active_session": session.session_id if session else None,
        "running": bool(session.running) if session else False,
        "failed": bool(session.failed) if session else False,
    }


@app.post("/api/decrypt")
async def decrypt(
    mode: str = Form("auto"),
    sip_pcap: UploadFile = File(...),
) -> Dict[str, Any]:
    session = CAPTURE_SERVICE.latest_session()
    if session is None or session.running:
        raise HTTPException(status_code=400, detail="Stop a capture session before decrypting")

    upload_path = session.uploads_dir / sip_pcap.filename
    content = await sip_pcap.read()
    upload_path.write_bytes(content)

    try:
        parsed = parse_sip_pcap(upload_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    call = _select_best_call(parsed.calls)
    if call is None:
        raise HTTPException(status_code=400, detail="No SIP call with SDP negotiation was found")
    call_cid = call.call_id or short_uuid()
    with correlation_context(call_cid):
        LOGGER.info("API decrypt request call_id=%s mode=%s", call.call_id, mode, extra={"category": "SRTP_DECRYPT"})

        streams = match_streams(call, session.host_files)
    if not streams:
        return {
            "call_id": call.call_id,
            "status": "failed",
            "message": "No RTP/SRTP streams from the call were found in the latest capture session",
            "results": [],
            "warnings": parsed.warnings,
        }

    # Prepare a concise per-stream log (visible tail only)
    log_lines: List[str] = LiveCorrelationLog(call_cid)
    log_lines.append(f"Call-ID: {call.call_id}")
    log_lines.append(f"Streams matched: {len(streams)}")

    encrypted_likely = any(
        ("SAVP" in (m.protocol or "")) or m.sdes_cryptos or m.dtls_fingerprints
        for m in call.media_sections
    )
    if encrypted_likely:
        log_lines.append("WARN: Encrypted media detected (SRTP). Attempting decryption...")

    # Always produce an "as captured" media pcap (may be SRTP or RTP).
    combined_dir = session.base_dir / "combined"
    combined_dir.mkdir(parents=True, exist_ok=True)
    per_stream_pcaps: List[Path] = []
    for s in streams:
        out = combined_dir / f"{s.stream_id}.pcap"
        out_p, _count = extract_stream_to_pcap(s, out)
        if out_p.exists():
            per_stream_pcaps.append(out_p)

    media_encrypted_pcap = combined_dir / "media_raw.pcap"
    if per_stream_pcaps:
        merge_pcaps(media_encrypted_pcap, per_stream_pcaps)

    results = DECRYPTION_SERVICE.decrypt_streams(mode=mode, call=call, streams=streams, output_dir=session.decrypted_dir)
    response_results: List[Dict[str, Any]] = []
    for item in results:
        log_lines.append(f"{item.stream_id} => {item.status} ({item.message})")
        response_results.append(
            {
                "stream_id": item.stream_id,
                "status": item.status,
                "message": item.message,
                "download": f"/downloads/{session.session_id}/decrypted/{item.output_file.name}" if item.output_file else None,
            }
        )

    # Build final outputs:
    # - media_decrypted.pcap: merged decrypted media (success only)
    # - sip_plus_media_decrypted.pcap: uploaded SIP pcap + decrypted media
    media_decrypted_pcap = combined_dir / "media_decrypted.pcap"
    sip_plus_media_decrypted_pcap = combined_dir / "SIP_plus_media_decrypted.pcap"
    decrypted_inputs = [item.output_file for item in results if item.output_file]

    if decrypted_inputs:
        merge_pcaps(media_decrypted_pcap, [p for p in decrypted_inputs if p is not None])
        merge_pcaps(sip_plus_media_decrypted_pcap, [upload_path, media_decrypted_pcap])
    _cleanup_local_raw_after_postprocess(session, log_lines, call_cid)
    # Correlation should not trigger RTP capture sync to S3.
    # S3 upload is handled in parallel by capture storage maintenance.

    return {
        "call_id": call.call_id,
        "status": "completed",
        "mode": mode,
        "encrypted_likely": encrypted_likely,
        "warnings": parsed.warnings,
        "streams": [
            {
                "stream_id": stream.stream_id,
                "host": stream.host_id,
                "packet_count": stream.packet_count,
            }
            for stream in streams
        ],
        "results": response_results,
        "log_tail": log_lines,
        "final_files": {
            "encrypted_media": _file_link(session, "combined", media_encrypted_pcap) if media_encrypted_pcap.exists() else None,
            "decrypted_media": _file_link(session, "combined", media_decrypted_pcap) if media_decrypted_pcap.exists() else None,
            "sip_plus_decrypted_media": _file_link(session, "combined", sip_plus_media_decrypted_pcap)
            if sip_plus_media_decrypted_pcap.exists()
            else None,
        },
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
    }


def _run_correlation_job_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute correlation in worker context while reusing the existing correlate() pipeline.
    """
    session = _hydrate_session_for_worker(payload)
    expected_session_id = str(payload.get("session_id", "")).strip()
    if expected_session_id and session.session_id != expected_session_id:
        raise ValueError(
            f"Correlation session changed while job was queued. expected={expected_session_id} current={session.session_id}"
        )
    upload_path = Path(str(payload.get("upload_path", "")).strip())
    if not upload_path.exists() or not upload_path.is_file():
        raise ValueError(f"Uploaded SIP pcap not found for job: {upload_path}")
    call_direction = str(payload.get("call_direction", "")).strip().lower()
    debug = str(payload.get("debug", "0"))

    data = upload_path.read_bytes()
    upload = UploadFile(filename=upload_path.name, file=io.BytesIO(data))
    try:
        return asyncio.run(correlate(sip_pcap=upload, call_direction=call_direction, debug=debug))
    finally:
        try:
            upload.file.close()
        except Exception:
            pass


def _hydrate_session_for_worker(payload: Dict[str, Any]) -> CaptureSession:
    """
    In split-process mode (run-app + run-worker), rebuild session context from disk.
    """
    upload_path = Path(str(payload.get("upload_path", "")).strip())
    if not upload_path.exists() or not upload_path.is_file():
        raise ValueError(f"Uploaded SIP pcap not found for job: {upload_path}")
    base_dir_raw = str(payload.get("base_dir", "")).strip()
    raw_dir_raw = str(payload.get("raw_dir", "")).strip()
    uploads_dir_raw = str(payload.get("uploads_dir", "")).strip()
    decrypted_dir_raw = str(payload.get("decrypted_dir", "")).strip()

    if base_dir_raw:
        base_dir = Path(base_dir_raw).expanduser().resolve()
    else:
        base_dir = upload_path.parent.parent
    if raw_dir_raw:
        raw_dir = Path(raw_dir_raw).expanduser().resolve()
    else:
        raw_dir = base_dir / "raw"
    if uploads_dir_raw:
        uploads_dir = Path(uploads_dir_raw).expanduser().resolve()
    else:
        uploads_dir = base_dir / "uploads"
    if decrypted_dir_raw:
        decrypted_dir = Path(decrypted_dir_raw).expanduser().resolve()
    else:
        decrypted_dir = base_dir / "decrypted"

    source_mode = str(payload.get("source_mode", "") or "").strip()
    raw_dir_managed = bool(payload.get("raw_dir_managed", source_mode != "local_reference"))
    if raw_dir_managed and not raw_dir.exists():
        raw_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.warning(
            "Raw directory was missing for job session; created dir=%s",
            raw_dir,
            extra={"category": "FILES"},
        )
    uploads_dir.mkdir(parents=True, exist_ok=True)
    decrypted_dir.mkdir(parents=True, exist_ok=True)
    expected_session_id = str(payload.get("session_id", "")).strip()
    session_id = expected_session_id or base_dir.name

    host_files: Dict[str, List[Path]] = {}
    host_files_payload = payload.get("host_files")
    if isinstance(host_files_payload, dict):
        for host_key, paths in host_files_payload.items():
            if not isinstance(paths, list):
                continue
            resolved_paths: List[Path] = []
            for path_value in paths:
                raw_path = str(path_value or "").strip()
                if not raw_path:
                    continue
                p = Path(raw_path).expanduser().resolve()
                if p.exists() and p.is_file():
                    resolved_paths.append(p)
            if resolved_paths:
                host_files[str(host_key)] = sorted(resolved_paths, key=lambda path: path.name)
    if not host_files:
        for p in sorted(raw_dir.glob("*.pcap")) + sorted(raw_dir.glob("*.pcapng")):
            host_key = _host_key_from_capture_filename(p.name)
            host_files.setdefault(host_key, []).append(p)

    session = CaptureSession(
        session_id=session_id,
        environment=str(payload.get("environment", "imported") or "imported"),
        region=str(payload.get("region", "imported") or "imported"),
        sub_regions=list(payload.get("sub_regions") or ["imported"]),
        bpf_filter=str(payload.get("filter", "imported") or "imported"),
        base_dir=base_dir,
        raw_dir=raw_dir,
        uploads_dir=uploads_dir,
        decrypted_dir=decrypted_dir,
        started_at=dt.datetime.utcnow(),
        stopped_at=dt.datetime.utcnow(),
        running=False,
        storage_mode=str(payload.get("storage_mode", "local") or "local"),
        storage_notice=(str(payload.get("storage_notice")) if payload.get("storage_notice") else None),
        source_mode=source_mode or "import_upload",
        raw_dir_managed=raw_dir_managed,
    )
    session.host_files = host_files
    session.host_packet_counts = {host_id: 0 for host_id in host_files}
    s3_source_objects_raw = payload.get("s3_source_objects")
    if isinstance(s3_source_objects_raw, dict):
        session.s3_source_objects = {
            str(host): [str(k) for k in keys if str(k).strip()]
            for host, keys in s3_source_objects_raw.items()
            if isinstance(keys, list)
        }
        for host in session.s3_source_objects.keys():
            session.host_packet_counts.setdefault(host, 0)
    s3_source_prefix = str(payload.get("s3_source_session_prefix", "")).strip()
    session.s3_source_session_prefix = s3_source_prefix or None

    # Bind rebuilt session into this worker process service context.
    CAPTURE_SERVICE._active_session = None  # type: ignore[attr-defined]
    CAPTURE_SERVICE._latest_session = session  # type: ignore[attr-defined]
    return session


@app.post("/api/jobs/correlate")
async def create_correlation_job(
    sip_pcap: UploadFile = File(...),
    call_direction: str = Form(""),
    debug: str = Form("0"),
) -> Dict[str, Any]:
    session = CAPTURE_SERVICE.latest_session()
    if session is None:
        raise HTTPException(
            status_code=400,
            detail="No media session available. Import a local media directory or an S3 media session before correlating.",
        )
    if session.storage_mode == "s3":
        CAPTURE_SERVICE.refresh_session_media_index(session)
    if session.running:
        raise HTTPException(status_code=400, detail="Stop a capture session before correlating")
    if not session.host_files and not session.s3_source_objects:
        raise HTTPException(
            status_code=400,
            detail="No media files loaded. Import a local media directory or select an S3 media session first.",
        )
    s3_block_reason = CAPTURE_SERVICE.s3_correlation_block_reason(session)
    if s3_block_reason:
        raise HTTPException(status_code=409, detail=s3_block_reason)
    direction = str(call_direction or "").strip().lower()
    if direction not in {"inbound", "outbound"}:
        raise HTTPException(status_code=400, detail="Call direction is required and must be Inbound or Outbound")

    upload_path = session.uploads_dir / sip_pcap.filename
    content = await sip_pcap.read()
    upload_path.write_bytes(content)
    payload = {
        "session_id": session.session_id,
        "upload_path": str(upload_path),
        "call_direction": direction,
        "debug": str(debug or "0"),
        "base_dir": str(session.base_dir),
        "raw_dir": str(session.raw_dir),
        "uploads_dir": str(session.uploads_dir),
        "decrypted_dir": str(session.decrypted_dir),
        "source_mode": str(getattr(session, "source_mode", "") or ""),
        "raw_dir_managed": bool(getattr(session, "raw_dir_managed", True)),
        "host_files": {
            str(host): [str(p) for p in paths]
            for host, paths in (session.host_files or {}).items()
        },
        "environment": session.environment,
        "region": session.region,
        "sub_regions": list(session.sub_regions),
        "filter": session.bpf_filter,
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
        "s3_source_objects": session.s3_source_objects,
        "s3_source_session_prefix": session.s3_source_session_prefix,
    }
    try:
        job = JOB_ORCHESTRATOR.submit("correlate", payload)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not queue correlation job: {exc}") from exc
    LOGGER.info(
        "Correlation job queued job_id=%s session_id=%s file=%s direction=%s",
        job.job_id,
        session.session_id,
        upload_path.name,
        direction,
        extra={"category": "RTP_SEARCH", "correlation_id": session.session_id},
    )
    return {
        "job_id": job.job_id,
        "status": job.status,
        "job_type": job.job_type,
        "created_at": job.created_at,
    }


@app.get("/api/jobs/{job_id}")
def get_job_status(job_id: str) -> Dict[str, Any]:
    job = JOB_ORCHESTRATOR.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job.job_id,
        "job_type": job.job_type,
        "status": job.status,
        "progress_step": job.progress_step,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


@app.get("/api/jobs/{job_id}/result")
def get_job_result(job_id: str) -> Dict[str, Any]:
    job = JOB_ORCHESTRATOR.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status in {"queued", "running"}:
        raise HTTPException(status_code=202, detail="Job still running")
    if job.status == "failed":
        raise HTTPException(status_code=400, detail=job.error or "Job failed")
    return {"job_id": job.job_id, "status": job.status, "result": job.result or {}}


@app.get("/api/jobs/{job_id}/events")
def get_job_events(job_id: str, after_seq: int = Query(0, ge=0)) -> Dict[str, Any]:
    job = JOB_ORCHESTRATOR.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    events = JOB_ORCHESTRATOR.list_events(job_id, after_seq=after_seq)
    return {
        "job_id": job_id,
        "events": [
            {"seq": e.seq, "ts": e.ts, "level": e.level, "message": e.message, "step": e.step}
            for e in events
        ],
    }


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> Dict[str, Any]:
    job = JOB_ORCHESTRATOR.cancel(job_id, reason="Correlation canceled by user")
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    LOGGER.warning(
        "Correlation cancellation requested job_id=%s status=%s",
        job_id,
        job.status,
        extra={"category": "RTP_SEARCH", "correlation_id": job_id},
    )
    return {
        "job_id": job.job_id,
        "status": job.status,
        "progress_step": job.progress_step,
        "error": job.error,
    }


@app.get("/api/jobs/{job_id}/events/stream")
async def stream_job_events(job_id: str, request: Request, after_seq: int = Query(0, ge=0)) -> StreamingResponse:
    if not JOB_ORCHESTRATOR.get(job_id):
        raise HTTPException(status_code=404, detail="Job not found")

    async def _iter():
        cursor = after_seq
        while True:
            if await request.is_disconnected():
                break
            events = JOB_ORCHESTRATOR.wait_for_events(job_id, after_seq=cursor, timeout=10.0)
            if not events:
                yield ": keep-alive\n\n"
                await asyncio.sleep(0.1)
                continue
            payload = [
                {"seq": e.seq, "ts": e.ts, "level": e.level, "message": e.message, "step": e.step}
                for e in events
            ]
            cursor = payload[-1]["seq"]
            yield f"data: {json.dumps({'job_id': job_id, 'events': payload})}\n\n"

    return StreamingResponse(
        _iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _format_log_banner(text: str, width: int = 67) -> str:
    """
    Build a centered banner line like:
    ========  <text>  ========
    with fixed total width.
    """
    label = f"  {str(text).strip()}  "
    if len(label) >= width:
        return label
    pad = width - len(label)
    left = pad // 2
    right = pad - left
    return f"{'=' * left}{label}{'=' * right}"


@app.post("/api/correlate")
async def correlate(
    sip_pcap: UploadFile = File(...),
    call_direction: str = Form(""),
    debug: str = Form("0"),
) -> Dict[str, Any]:
    session = CAPTURE_SERVICE.latest_session()
    if session is None:
        raise HTTPException(
            status_code=400,
            detail="No media session available. Import a local media directory or an S3 media session before correlating.",
        )
    if session.storage_mode == "s3":
        CAPTURE_SERVICE.refresh_session_media_index(session)
    if session.running:
        raise HTTPException(status_code=400, detail="Stop a capture session before correlating")
    if not session.host_files and not session.s3_source_objects:
        raise HTTPException(
            status_code=400,
            detail="No media files loaded. Import a local media directory or select an S3 media session first.",
        )
    s3_block_reason = CAPTURE_SERVICE.s3_correlation_block_reason(session)
    if s3_block_reason:
        raise HTTPException(status_code=409, detail=s3_block_reason)

    upload_path = session.uploads_dir / sip_pcap.filename
    content = await sip_pcap.read()
    upload_path.write_bytes(content)

    try:
        parsed = parse_sip_pcap(upload_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    direction = str(call_direction or "").strip().lower()
    if direction not in {"inbound", "outbound"}:
        raise HTTPException(status_code=400, detail="Call direction is required and must be Inbound or Outbound")

    # Use new B2BUA-aware correlation with multi-Call-ID grouping
    try:
        call, correlation_ctx, all_call_ids = _select_best_call_with_grouping(parsed, direction)
    except Exception as exc:
        # Fallback to old method if new correlation fails
        LOGGER.warning(
            "New correlation failed, falling back to legacy method: %s",
            exc,
            extra={"category": "SIP_CORRELATION"},
        )
        call = _select_best_call(parsed.calls)
        correlation_ctx = None
        all_call_ids = [call.call_id] if call else []

    if call is None:
        raise HTTPException(status_code=400, detail="No SIP call with SDP negotiation was found")
    
    call_cid = call.call_id or short_uuid()
    invites = sorted(
        [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"],
        key=lambda m: m.ts,
    )
    invites_with_sdp = [m for m in invites if m.has_sdp and m.media_sections]
    analysis_msg = invites_with_sdp[0] if invites_with_sdp else (invites[0] if invites else None)
    if analysis_msg is None:
        analysis_msg = next((m for m in sorted(call.messages, key=lambda m: m.ts) if m.packet_number is not None), None)
    analysis_packet = analysis_msg.packet_number if analysis_msg else None
    log_lines: List[str] = LiveCorrelationLog(call_cid)
    log_lines.append(_format_log_banner("Step 1: Parse SIP pcap"))
    
    # Show all Call-IDs if multiple
    if len(all_call_ids) > 1:
        log_lines.append(f"CallID(s): {'; '.join(all_call_ids)}")
    else:
        log_lines.append(f"Call-ID: {call.call_id}")
    
    # Add RTP Engine detection info from new correlation
    if correlation_ctx and correlation_ctx.rtp_engine.detected:
        rtp_eng = correlation_ctx.rtp_engine
        log_lines.append(f"INFO: RTP Engine detected: YES")
        log_lines.append(f"INFO:   - SDP c= changed: {rtp_eng.original_sdp_ip} -> {rtp_eng.changed_sdp_ip}")
        log_lines.append(f"INFO:   - Change detected at packet: {rtp_eng.sdp_change_packet}")
        log_lines.append(f"INFO:   - Engine IP (packet src_ip): {rtp_eng.engine_ip}")
    else:
        log_lines.append("INFO: RTP Engine detected: NO")
    
    log_lines.append(_format_log_banner("Step 2: Build RTP filters"))
    log_lines.append("INFO: RTP request/reply media IP+ports are auto-detected from SIP INVITE/200 OK m=audio.")
    log_lines.append(f"INFO: Direction: {direction}")
    log_lines.append(f"INFO: Analysis packet={analysis_packet}")

    def _raise_correlation_http_error(message: str) -> None:
        raise HTTPException(status_code=400, detail={"message": message, "log_tail": log_lines})

    with correlation_context(call_cid):
        LOGGER.info(
            "API correlate request call_id=%s media_files=%s debug=%s direction=%s analysis_packet=%s",
            call.call_id,
            (sum(len(v) for v in session.host_files.values()) + sum(len(v) for v in session.s3_source_objects.values())),
            debug,
            direction,
            analysis_packet,
            extra={"category": "RTP_SEARCH"},
        )
        
        # Add structured logging from new B2BUA correlation context
        if correlation_ctx:
            for line in correlation_ctx.log_lines:
                log_lines.append(line)
        
        try:
            negotiation = _resolve_negotiation_context(call, direction)
        except ValueError as exc:
            log_lines.append(f"ERROR: {exc}")
            _raise_correlation_http_error(str(exc))
            return
        log_lines.append(
            "INFO: Negotiation context "
            f"first_invite_src={negotiation['first_invite_source_ip']} "
            f"first_invite_dst={negotiation['first_invite_destination_ip']} "
            f"last_host={negotiation['last_negotiation_host_ip']} "
            f"carrier={negotiation['carrier_ip']} "
            f"core={negotiation['core_ip']} "
            f"first_invite_packet={negotiation['first_invite_packet']} "
            f"last_packet_invite={negotiation['last_packet_invite']}"
        )
        LOGGER.info(
            "Negotiation context first_invite_src=%s first_invite_dst=%s last_host=%s carrier=%s core=%s first_invite_packet=%s last_packet_invite=%s",
            negotiation["first_invite_source_ip"],
            negotiation["first_invite_destination_ip"],
            negotiation["last_negotiation_host_ip"],
            negotiation["carrier_ip"],
            negotiation["core_ip"],
            negotiation["first_invite_packet"],
            negotiation["last_packet_invite"],
            extra={"category": "SIP", "correlation_id": call_cid},
        )
        invite_cipher_packet = None
        ok_200_cipher_packet = None
        carrier_invite_packet = None
        carrier_200ok_packet = None
        core_invite_packet = None
        core_200ok_packet = None
        if correlation_ctx:
            if correlation_ctx.carrier_leg:
                carrier_invite_packet = correlation_ctx.carrier_leg.invite_packet
                carrier_200ok_packet = correlation_ctx.carrier_leg.ok_200_packet
            if correlation_ctx.core_leg:
                core_invite_packet = correlation_ctx.core_leg.invite_packet
                core_200ok_packet = correlation_ctx.core_leg.ok_200_packet
            invite_cipher_packet = carrier_invite_packet
            ok_200_cipher_packet = carrier_200ok_packet
        try:
            if invite_cipher_packet is None or ok_200_cipher_packet is None:
                inline_invite, inline_ok = _select_invite_and_ok_for_direction(call, negotiation, direction)
                invite_cipher_packet = inline_invite.packet_number
                ok_200_cipher_packet = inline_ok.packet_number
        except ValueError:
            pass
        try:
            if carrier_invite_packet is None or carrier_200ok_packet is None:
                carrier_invite, carrier_ok = _select_carrier_request_reply_messages(call, negotiation, direction)
                carrier_invite_packet = carrier_invite.packet_number
                carrier_200ok_packet = carrier_ok.packet_number
        except ValueError:
            pass
        try:
            if core_invite_packet is None or core_200ok_packet is None:
                core_invite, core_ok = _select_core_request_reply_messages(call, negotiation, direction)
                core_invite_packet = core_invite.packet_number
                core_200ok_packet = core_ok.packet_number
        except ValueError:
            pass
        LOGGER.info(
            "Packet selection analysis_packet=%s invite_cipher_packet=%s 200ok_cipher_packet=%s carrier_invite_packet=%s carrier_200ok_packet=%s core_invite_packet=%s core_200ok_packet=%s",
            analysis_packet,
            invite_cipher_packet,
            ok_200_cipher_packet,
            carrier_invite_packet,
            carrier_200ok_packet,
            core_invite_packet,
            core_200ok_packet,
            extra={"category": "SIP", "correlation_id": call_cid},
        )
        log_lines.append(
            "INFO: Packet selection "
            f"analysis_packet={analysis_packet} "
            f"invite_cipher_packet={invite_cipher_packet} 200ok_cipher_packet={ok_200_cipher_packet} "
            f"carrier_invite_packet={carrier_invite_packet} carrier_200ok_packet={carrier_200ok_packet} "
            f"core_invite_packet={core_invite_packet} core_200ok_packet={core_200ok_packet}"
        )
        selected_crypto: List[SdesCryptoMaterial] = []
        crypto_warning: str | None = None
        try:
            if invite_cipher_packet is not None and ok_200_cipher_packet is not None:
                selected_crypto = _select_inline_crypto_for_packet_pair(
                    call,
                    invite_cipher_packet,
                    ok_200_cipher_packet,
                )
            else:
                selected_crypto = _select_inline_crypto_for_direction(call, negotiation, direction)
        except ValueError as exc:
            crypto_warning = str(exc)
            LOGGER.warning(
                "Inline selection unavailable; continuing without explicit SDES materials selected_invite_packet=%s selected_200ok_packet=%s reason=%s",
                invite_cipher_packet,
                ok_200_cipher_packet,
                crypto_warning,
                extra={"category": "SDES_KEYS", "correlation_id": call_cid},
            )
        try:
            if correlation_ctx and correlation_ctx.carrier_leg and correlation_ctx.carrier_leg.source_media and correlation_ctx.carrier_leg.destination_media:
                carrier_request_port = correlation_ctx.carrier_leg.source_media.rtp_port
                carrier_reply_port = correlation_ctx.carrier_leg.destination_media.rtp_port
                carrier_request_ip = correlation_ctx.carrier_leg.source_media.rtp_ip
                carrier_reply_ip = correlation_ctx.carrier_leg.destination_media.rtp_ip
            else:
                carrier_request_port, carrier_reply_port, carrier_request_ip, carrier_reply_ip = _resolve_carrier_request_reply_ports(call, negotiation, direction)
        except ValueError as exc:
            log_lines.append(f"ERROR: {exc}")
            _raise_correlation_http_error(str(exc))
            return
        try:
            if correlation_ctx and correlation_ctx.core_leg and correlation_ctx.core_leg.source_media and correlation_ctx.core_leg.destination_media:
                core_request_port = correlation_ctx.core_leg.source_media.rtp_port
                core_reply_port = correlation_ctx.core_leg.destination_media.rtp_port
                core_request_ip = correlation_ctx.core_leg.source_media.rtp_ip
                core_reply_ip = correlation_ctx.core_leg.destination_media.rtp_ip
            else:
                core_request_port, core_reply_port, core_request_ip, core_reply_ip = _resolve_core_request_reply_ports(call, negotiation, direction)
        except ValueError as exc:
            log_lines.append(f"ERROR: {exc}")
            _raise_correlation_http_error(str(exc))
            return
        carrier_200ok_audio_proto = _carrier_received_200ok_audio_proto(call, negotiation)
        encrypted_expected, encrypted_reasons = _is_media_encrypted_expected(call, direction, negotiation)
        LOGGER.info(
            "Encryption expectation detected=%s reasons=%s",
            encrypted_expected,
            encrypted_reasons,
            extra={"category": "SDP", "correlation_id": call_cid},
        )
        LOGGER.info(
            "Carrier-received 200 OK audio protocol=%s",
            carrier_200ok_audio_proto or "not-found",
            extra={"category": "SDP", "correlation_id": call_cid},
        )
        LOGGER.info(
            "Carrier request/reply RTP media resolved from SIP request_ip=%s request_port=%s reply_ip=%s reply_port=%s sip_method_request=%s sip_method_reply=%s invite_packet_number=%s reply_packet_number=%s",
            carrier_request_ip,
            carrier_request_port,
            carrier_reply_ip,
            carrier_reply_port,
            "INVITE",
            "200OK",
            carrier_invite_packet,
            carrier_200ok_packet,
            extra={"category": "SDP", "correlation_id": call_cid},
        )
        LOGGER.info(
            "Core request/reply RTP media resolved from SIP request_ip=%s request_port=%s reply_ip=%s reply_port=%s sip_method_request=%s sip_method_reply=%s invite_packet_number=%s reply_packet_number=%s",
            core_request_ip,
            core_request_port,
            core_reply_ip,
            core_reply_port,
            "INVITE",
            "200OK",
            core_invite_packet,
            core_200ok_packet,
            extra={"category": "SDP", "correlation_id": call_cid},
        )
        steps, endpoint_debug = _build_manual_rtp_steps(
            direction=direction,
            carrier_request_ip=carrier_request_ip or str(negotiation["carrier_ip"]),
            carrier_reply_ip=carrier_reply_ip or str(negotiation["carrier_ip"]),
            carrier_request_port=carrier_request_port,
            carrier_reply_port=carrier_reply_port,
            core_request_port=core_request_port,
            core_request_ip=core_request_ip or str(negotiation["core_ip"]),
            core_reply_ip=core_reply_ip or str(negotiation["core_ip"]),
            core_reply_port=core_reply_port,
        )

    # Save context for later steps.
    session.last_sip_pcap = upload_path
    session.last_call_id = call.call_id

    # Identify media endpoints in the uploaded SIP pcap (offer/answer typically yields 2/4/6/... endpoints).
    all_endpoints = {(m.connection_ip, m.port) for m in call.media_sections if m.connection_ip and m.port}
    endpoints_sorted = sorted(all_endpoints, key=lambda item: (item[0], item[1]))

    encrypted_likely = any(
        ("SAVP" in (m.protocol or "")) or m.sdes_cryptos or m.dtls_fingerprints
        for m in call.media_sections
    )

    # Build per-stream extraction and final outputs in one shot (auto-detect decrypt mode).
    if parsed.warnings:
        log_lines.append(f"WARN: SIP parse warnings: {len(parsed.warnings)}")
        for w in parsed.warnings[:5]:
            log_lines.append(f"WARN: {w}")

    log_lines.append(
        "INFO: Carrier/Core resolved from SIP: "
        f"carrier={negotiation['carrier_ip']} core={negotiation['core_ip']} "
        f"(first_invite_src={negotiation['first_invite_source_ip']} last_host={negotiation['last_negotiation_host_ip']})"
    )
    log_lines.append(
        "INFO: Carrier request/reply RTP from SIP m=audio: "
        f"request_ip={carrier_request_ip} request_port={carrier_request_port} "
        f"reply_ip={carrier_reply_ip} reply_port={carrier_reply_port} "
        "sip_method_request=INVITE sip_method_reply=200OK "
        f"invite_packet_number={carrier_invite_packet} reply_packet_number={carrier_200ok_packet}"
    )
    log_lines.append(
        "INFO: Core request/reply RTP from SIP m=audio: "
        f"request_ip={core_request_ip} request_port={core_request_port} "
        f"reply_ip={core_reply_ip} reply_port={core_reply_port} "
        "sip_method_request=INVITE sip_method_reply=200OK "
        f"invite_packet_number={core_invite_packet} reply_packet_number={core_200ok_packet}"
    )
    log_lines.append(
        "INFO: Carrier-received 200 OK m=audio "
        f"protocol={carrier_200ok_audio_proto or 'not-found'} packet_number={carrier_200ok_packet}"
    )
    if crypto_warning:
        log_lines.append(
            "WARN: SDES inline selection unavailable: "
            f"{crypto_warning} selected_invite_packet={invite_cipher_packet} selected_200ok_packet={ok_200_cipher_packet}"
        )
        if encrypted_expected:
            log_lines.append(
                "WARN: Media appears encrypted but no inline key is available. "
                f"Files will be marked as no-decrypt-need. selected_invite_packet={invite_cipher_packet} selected_200ok_packet={ok_200_cipher_packet}"
            )
        else:
            log_lines.append("INFO: Media does not appear encrypted. Files will be marked as no-decrypt-need.")
    elif selected_crypto:
        log_lines.append("INFO: SDES material selected for decrypt phase:")
        for line in _selected_crypto_log_lines(
            selected_crypto,
            direction,
            request_packet_number=invite_cipher_packet,
            reply_packet_number=ok_200_cipher_packet,
        ):
            log_lines.append(f"INFO: {line}")
            LOGGER.info(
                "Decrypt material selected %s",
                line,
                extra={"category": "SDES_KEYS", "correlation_id": call_cid},
            )
    else:
        log_lines.append("INFO: No explicit SDES material selected for decrypt phase.")
    # Commented out: These filter logs show incomplete data at this stage
    # for line in endpoint_debug:
    #     log_lines.append(f"INFO: {line}")

    # Detect actual RTP Engine IP from PCAP files per instance (if RTP Engine is present)
    rtpengine_ip_per_instance: Dict[str, str] = {}  # Maps instance_id -> detected_ip
    if correlation_ctx and correlation_ctx.rtp_engine.detected:
        log_lines.append(_format_log_banner("RTP Engine IP Detection"))
        log_lines.append("INFO: RTP Engine detected in SIP signaling. Detecting actual IP per instance from capture files...")
        
        # Get media PCAPs for detection
        temp_media_pcaps = _materialize_media_pcaps_for_correlation(session, call_cid, [])
        
        if temp_media_pcaps:
            # Extract known IPs (carrier and core) to exclude from detection
            carrier_ips = set()
            core_ips = set()
            
            if correlation_ctx.carrier_leg:
                if correlation_ctx.carrier_leg.source_ip:
                    carrier_ips.add(correlation_ctx.carrier_leg.source_ip)
                if correlation_ctx.carrier_leg.destination_ip:
                    carrier_ips.add(correlation_ctx.carrier_leg.destination_ip)
                if correlation_ctx.carrier_leg.source_media and correlation_ctx.carrier_leg.source_media.rtp_ip:
                    carrier_ips.add(correlation_ctx.carrier_leg.source_media.rtp_ip)
            
            if correlation_ctx.core_leg:
                if correlation_ctx.core_leg.source_ip:
                    core_ips.add(correlation_ctx.core_leg.source_ip)
                if correlation_ctx.core_leg.destination_ip:
                    core_ips.add(correlation_ctx.core_leg.destination_ip)
                if correlation_ctx.core_leg.destination_media and correlation_ctx.core_leg.destination_media.rtp_ip:
                    core_ips.add(correlation_ctx.core_leg.destination_media.rtp_ip)
            
            # Group PCAPs by RTP Engine instance
            pcap_groups = _group_pcaps_by_rtp_instance(temp_media_pcaps)
            log_lines.append(f"INFO: Found {len(pcap_groups)} RTP Engine instance group(s)")
            
            # Detect IP for each RTP Engine instance
            for instance_id, instance_pcaps in sorted(pcap_groups.items()):
                if instance_id is None:
                    log_lines.append(f"INFO: Skipping {len(instance_pcaps)} file(s) without RTP Engine instance identifier")
                    continue
                
                log_lines.append(f"INFO: Processing instance '{instance_id}' with {len(instance_pcaps)} file(s)")
                
                # Try to detect from first few files of this instance
                detected_ip = None
                for pcap_file in instance_pcaps[:3]:  # Check first 3 files of this instance
                    detected_ip = detect_rtpengine_ip_from_pcap(
                        pcap_file,
                        carrier_ips=carrier_ips,
                        core_ips=core_ips,
                        max_packets=5,
                    )
                    if detected_ip:
                        rtpengine_ip_per_instance[instance_id] = detected_ip
                        log_lines.append(f"INFO:   Instance '{instance_id}' IP detected: {detected_ip} (from {pcap_file.name})")
                        break
                
                if not detected_ip:
                    log_lines.append(f"WARN:   Could not detect IP for instance '{instance_id}', will use SDP-announced IP")
            
            # Log comparison with SDP announced IP
            if rtpengine_ip_per_instance:
                log_lines.append(f"INFO: SDP announced IP: {correlation_ctx.rtp_engine.changed_sdp_ip}")
                unique_detected_ips = set(rtpengine_ip_per_instance.values())
                if len(unique_detected_ips) > 1:
                    log_lines.append(f"INFO: Multiple RTP Engine IPs detected: {', '.join(sorted(unique_detected_ips))}")
                elif unique_detected_ips and list(unique_detected_ips)[0] != correlation_ctx.rtp_engine.changed_sdp_ip:
                    log_lines.append(f"INFO: IP mismatch detected - using actual IPs in filters")
            else:
                log_lines.append("WARN: No RTP Engine IPs detected from any instance")
        else:
            log_lines.append("WARN: No media PCAPs available for RTP Engine IP detection")

    # Apply RTP filters per PCAP file using instance-specific IPs
    log_lines.append(_format_log_banner("Step 3: Apply RTP filters"))
    media_pcaps = _materialize_media_pcaps_for_correlation(session, call_cid, log_lines)
    log_lines.append(f"INFO: Media capture files available: {len(media_pcaps)}")
    
    if rtpengine_ip_per_instance:
        log_lines.append("INFO: Using per-instance RTP Engine IP detection for filters")
    else:
        log_lines.append("INFO: Using standard filter construction (no instance detection)")

    step_results: List[Dict[str, object]] = []
    combined_dir = session.base_dir / "combined"
    filtered_dir = session.base_dir / "filtered"
    filtered_dir.mkdir(parents=True, exist_ok=True)
    filtered_files: List[Path] = []
    
    # Track filter statistics per instance
    instance_filter_stats: Dict[str, Dict[str, int]] = {}  # instance_id -> {files_checked, files_filtered}
    
    # Thread-safe logging and stats accumulation
    log_lock = threading.Lock()
    
    def add_log_line(line: str) -> None:
        """Thread-safe log line appender"""
        with log_lock:
            log_lines.append(line)
    
    def update_instance_stats(inst_id: Optional[str], checked: bool = False, filtered: bool = False) -> None:
        """Thread-safe instance stats updater"""
        if inst_id:
            with log_lock:
                if inst_id not in instance_filter_stats:
                    instance_filter_stats[inst_id] = {"files_checked": 0, "files_filtered": 0}
                if checked:
                    instance_filter_stats[inst_id]["files_checked"] += 1
                if filtered:
                    instance_filter_stats[inst_id]["files_filtered"] += 1

    # Determine number of parallel workers
    max_workers = min(MAX_PARALLEL_FILTER_WORKERS, len(media_pcaps), os.cpu_count() or 4)
    add_log_line(f"INFO: Processing {len(media_pcaps)} capture files...")
    add_log_line("INFO: Analyzing packets and building filters for each RTP Engine instance...")
    add_log_line("INFO: This may take a few moments - results will appear as processing completes")
    
    # Process files in parallel using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = {}
        for pcap_idx, pcap_file in enumerate(media_pcaps, start=1):
            instance_id = _extract_rtp_engine_instance(pcap_file.name)
            rtpengine_actual_ip = rtpengine_ip_per_instance.get(instance_id) if instance_id else None
            
            future = executor.submit(
                _process_single_pcap_with_filter,
                pcap_file,
                pcap_idx,
                len(media_pcaps),
                instance_id,
                rtpengine_actual_ip,
                correlation_ctx,
                filtered_dir,
                call_cid,
            )
            futures[future] = (pcap_file, pcap_idx, instance_id)
        
        # Collect results as they complete
        completed = 0
        for future in as_completed(futures):
            pcap_file, pcap_idx, instance_id = futures[future]
            completed += 1
            
            try:
                result = future.result()
                
                if result["status"] == "success":
                    # Log combined filter
                    add_log_line(f"COMBINED FILTER: {result['filter']}")
                    
                    # Log processing info
                    instance_label = f"instance={instance_id}" if instance_id else "no_instance"
                    rtpengine_ip_used = rtpengine_ip_per_instance.get(instance_id) if instance_id else None
                    ip_label = f"ip={rtpengine_ip_used}" if rtpengine_ip_used else "ip=sdp_announced"
                    add_log_line(
                        f"  Scan complete: file={completed}/{len(media_pcaps)} name={pcap_file.name} "
                        f"{instance_label} {ip_label}"
                    )
                    add_log_line(f"  File: {pcap_file.name} -> packets={result['packets']} KEEP")
                    add_log_line(f"  SUCCESS: {pcap_file.name} filtered (packets={result['packets']})")
                    
                    with log_lock:
                        filtered_files.append(result["output"])
                    
                    update_instance_stats(instance_id, checked=True, filtered=True)
                    
                elif result["status"] == "skipped":
                    reason = result.get("reason", "unknown")
                    if reason == "no_filters":
                        add_log_line(
                            f"  File {completed}/{len(media_pcaps)}: {pcap_file.name} -> SKIP (no available filters)"
                        )
                    else:
                        # Log combined filter even for skipped files
                        if "filter" in result:
                            add_log_line(f"COMBINED FILTER: {result['filter']}")
                        
                        instance_label = f"instance={instance_id}" if instance_id else "no_instance"
                        rtpengine_ip_used = rtpengine_ip_per_instance.get(instance_id) if instance_id else None
                        ip_label = f"ip={rtpengine_ip_used}" if rtpengine_ip_used else "ip=sdp_announced"
                        add_log_line(
                            f"  Scan complete: file={completed}/{len(media_pcaps)} name={pcap_file.name} "
                            f"{instance_label} {ip_label}"
                        )
                        add_log_line(f"  File: {pcap_file.name} -> packets={result['packets']} SKIP")
                        
                        update_instance_stats(instance_id, checked=True, filtered=False)
                        
                else:  # error
                    add_log_line(f"  ERROR: {pcap_file.name} processing failed: {result.get('error', 'unknown error')}")
                    update_instance_stats(instance_id, checked=True, filtered=False)
                    
            except Exception as exc:
                add_log_line(f"  ERROR: {pcap_file.name} unexpected error: {exc}")
    
    # Log per-instance statistics
    if instance_filter_stats:
        log_lines.append("INFO: Per-instance filtering statistics:")
        for inst_id, stats in sorted(instance_filter_stats.items()):
            log_lines.append(
                f"INFO:   {inst_id}: checked={stats['files_checked']} filtered={stats['files_filtered']}"
            )
    
    # Build step_results summary using last built filters (for backward compatibility)
    if correlation_ctx:
        # Use fallback IP=None to get generic filter summary
        summary_steps = build_tshark_filters(correlation_ctx, None)
        for step in summary_steps:
            step_num = int(step["step"])
            leg_key = str(step["leg_key"])
            available = bool(step["available"])
            filter_expr = str(step.get("tshark_filter") or "")
            
            if not available or not filter_expr:
                reason = str(step.get("reason") or "unavailable")
                step_results.append(
                    {
                        "step": step_num,
                        "leg_key": leg_key,
                        "available": False,
                        "reason": reason,
                        "filter": None,
                        "files_checked": len(media_pcaps),
                        "files_filtered": 0,
                    }
                )
            else:
                step_results.append(
                    {
                        "step": step_num,
                        "leg_key": leg_key,
                        "available": True,
                        "reason": None,
                        "filter": filter_expr,
                        "files_checked": len(media_pcaps),
                        "files_filtered": len(filtered_files),
                        "execution_mode": "per_instance",
                    }
                )

    step_results.sort(key=lambda item: int(item.get("step", 0)))

    if not filtered_files:
        log_lines.append("ERROR: No filtered RTP files were created (threshold > 1 not met).")
        log_lines.append(
            f"No RTP/SRTP streams were found for uploaded SIP pcap {upload_path.name}. "
            "Please verify the media files and call direction."
        )
        _cleanup_local_raw_after_postprocess(session, log_lines, call_cid)
        return {
            "call_id": call.call_id,
            "warnings": parsed.warnings,
            "media_endpoints_in_uploaded_pcap": [{"ip": ip, "port": port} for (ip, port) in endpoints_sorted],
            "media_endpoints_count": len(all_endpoints),
            "encrypted_likely": encrypted_likely,
            "streams": [],
            "message": (
                f"No RTP/SRTP streams were found for uploaded SIP pcap {upload_path.name}. "
                "Please verify media files, call direction, and filters."
            ),
            "log_tail": log_lines,
            "rtp_src_filters": step_results,
            "detected_leg_details": _detected_leg_details(
                negotiation,
                carrier_request_ip,
                carrier_reply_ip,
                carrier_request_port,
                carrier_reply_port,
                core_request_ip,
                core_reply_ip,
                core_request_port,
                core_reply_port,
            ),
            "final_files": {
                "encrypted_media": None,
                "decrypted_media": None,
                "sip_plus_decrypted_media": None,
            },
        }

    combined_dir.mkdir(parents=True, exist_ok=True)
    log_lines.append(_format_log_banner("Step 4: Build media files"))
    media_encrypted_pcap = combined_dir / "media_raw.pcap"
    merge_pcaps(media_encrypted_pcap, filtered_files)
    log_lines.append(f"media_raw.pcap created from {len(filtered_files)} filtered files")

    media_decrypted_pcap = combined_dir / "media_decrypted.pcap"
    sip_plus_media_decrypted_pcap = combined_dir / "SIP_plus_media_decrypted.pcap"
    log_lines.append(_format_log_banner("Step 5: Detect encryption and decrypt files"))
    if selected_crypto:
        log_lines.append("INFO: Decrypt will use selected SDES materials (suite/inline):")
        for line in _selected_crypto_log_lines(
            selected_crypto,
            direction,
            request_packet_number=invite_cipher_packet,
            reply_packet_number=ok_200_cipher_packet,
        ):
            log_lines.append(f"INFO: {line}")
    processed_files: List[Path] = []
    decrypted_count = 0
    no_decrypt_count = 0
    decrypted_files: List[Path] = []
    no_decrypt_files: List[Path] = []
    for f in filtered_files:
        prefix = f.stem.replace("-filtered", "")
        try:
            if direction == "outbound":
                if encrypted_expected:
                    # Outbound: when SIP negotiation indicates SRTP, always attempt decrypt.
                    # This avoids false negatives from dissector-based encrypted detection.
                    log_lines.append(
                        f"{f.name}: encrypted_detected=True (from SIP negotiation); forcing decrypt attempt"
                    )
                    result = DECRYPTION_SERVICE.decrypt_or_copy_pcap(
                        call=call,
                        input_pcap=f,
                        output_dir=session.decrypted_dir,
                        output_prefix=prefix,
                        crypto_materials=selected_crypto,
                        encrypted_expected=True,
                    )
                else:
                    file_encrypted = _detect_encrypted_filtered_file(
                        f, default_encrypted=encrypted_expected, correlation_id=call_cid
                    )
                    log_lines.append(f"{f.name}: encrypted_detected={file_encrypted}")
                    if file_encrypted:
                        result = DECRYPTION_SERVICE.decrypt_or_copy_pcap(
                            call=call,
                            input_pcap=f,
                            output_dir=session.decrypted_dir,
                            output_prefix=prefix,
                            crypto_materials=selected_crypto,
                            encrypted_expected=True,
                        )
                    else:
                        out = session.decrypted_dir / f"{prefix}-no-decrypt-need.pcap"
                        shutil.copy2(f, out)
                        result = DecryptionResult(
                            stream_id=prefix,
                            status="copied",
                            message="Stream not encrypted; copied as no-decrypt-need",
                            output_file=out,
                        )
            else:
                # Inbound: keep existing behavior.
                result = DECRYPTION_SERVICE.decrypt_or_copy_pcap(
                    call=call,
                    input_pcap=f,
                    output_dir=session.decrypted_dir,
                    output_prefix=prefix,
                    crypto_materials=selected_crypto,
                    encrypted_expected=encrypted_expected,
                )
        except Exception as exc:
            fallback = session.decrypted_dir / f"{prefix}-no-decrypt-need.pcap"
            shutil.copy2(f, fallback)
            result = DecryptionResult(
                stream_id=prefix,
                status="copied",
                message=f"Decrypt processing failed ({exc}); copied as no-decrypt-need",
                output_file=fallback,
            )
            LOGGER.exception(
                "Decrypt processing failed for filtered file=%s; fallback copy created=%s",
                f,
                fallback,
                extra={"category": "ERRORS", "correlation_id": call_cid},
            )
        if result.output_file:
            processed_files.append(result.output_file)
            if result.output_file.name.endswith("-decrypted.pcap"):
                decrypted_count += 1
                decrypted_files.append(result.output_file)
            elif result.output_file.name.endswith("-no-decrypt-need.pcap"):
                no_decrypt_count += 1
                no_decrypt_files.append(result.output_file)
        log_lines.append(f"{f.name} => {result.status} ({result.message})")

    log_lines.append(
        f"INFO: Processed filtered files: decrypted={decrypted_count} no-decrypt-need={no_decrypt_count} total={len(processed_files)}"
    )

    log_lines.append(_format_log_banner("Step 6: Merge processed media with SIP"))
    if processed_files:
        filtered_names = [p.name for p in filtered_files]
        no_decrypt_names = [p.name for p in no_decrypt_files]
        decrypted_names = [p.name for p in decrypted_files]
        if direction == "outbound":
            # Outbound required logic:
            # media_raw = filtered + no-decrypt-need
            merge_pcaps(media_encrypted_pcap, list(filtered_files) + list(no_decrypt_files))
            log_lines.append(
                f"media_raw.pcap rebuilt from filtered({len(filtered_files)}) + no-decrypt-need({len(no_decrypt_files)})"
            )
            if filtered_names:
                log_lines.append("Filtered files:")
                for name in filtered_names:
                    log_lines.append(f"- {name}")
            if no_decrypt_names:
                log_lines.append("No-decrypt-need files:")
                for name in no_decrypt_names:
                    log_lines.append(f"- {name}")
            # media_decrypted = decrypted + no-decrypt-need
            merge_pcaps(media_decrypted_pcap, list(decrypted_files) + list(no_decrypt_files))
            log_lines.append(
                f"media_decrypted.pcap created from decrypted({len(decrypted_files)}) + no-decrypt-need({len(no_decrypt_files)})"
            )
            if decrypted_names:
                log_lines.append("Decrypted files:")
                for name in decrypted_names:
                    log_lines.append(f"- {name}")
            if no_decrypt_names:
                log_lines.append("No-decrypt-need files (included in media_decrypted.pcap):")
                for name in no_decrypt_names:
                    log_lines.append(f"- {name}")
        else:
            # Inbound: keep existing behavior.
            merge_pcaps(media_decrypted_pcap, processed_files)
            log_lines.append("media_decrypted.pcap created")
            used_names = [p.name for p in processed_files]
            if used_names:
                log_lines.append("Processed files merged into media_decrypted.pcap:")
                for name in used_names:
                    log_lines.append(f"- {name}")
        merge_pcaps(sip_plus_media_decrypted_pcap, [upload_path, media_decrypted_pcap])
        log_lines.append("SIP_plus_media_decrypted.pcap created")
        log_lines.append("SIP merge inputs:")
        log_lines.append(f"- {upload_path.name}")
        log_lines.append(f"- {media_decrypted_pcap.name}")
    else:
        log_lines.append("ERROR: No processed files created after decrypt/no-decrypt step")
    CAPTURE_SERVICE.sync_session_storage(session, include_running=False, force=False)
    _cleanup_local_raw_after_postprocess(session, log_lines, call_cid)

    return {
        "call_id": call.call_id,
        "warnings": parsed.warnings,
        "media_endpoints_in_uploaded_pcap": [{"ip": ip, "port": port} for (ip, port) in endpoints_sorted],
        "media_endpoints_count": len(all_endpoints),
        "encrypted_likely": encrypted_likely,
        "streams": [{"stream_id": p.stem, "host": "filtered", "packet_count": 0} for p in filtered_files],
        "message": "Correlation completed" if filtered_files else "No RTP/SRTP streams from the call were found in the latest capture session",
        "log_tail": log_lines,
        "rtp_src_filters": step_results,
        "detected_leg_details": _detected_leg_details(
            negotiation,
            carrier_request_ip,
            carrier_reply_ip,
            carrier_request_port,
            carrier_reply_port,
            core_request_ip,
            core_reply_ip,
            core_request_port,
            core_reply_port,
        ),
        "final_files": {
            "encrypted_media": _file_link(session, "combined", media_encrypted_pcap) if media_encrypted_pcap.exists() else None,
            "decrypted_media": _file_link(session, "combined", media_decrypted_pcap) if media_decrypted_pcap.exists() else None,
            "sip_plus_decrypted_media": _file_link(session, "combined", sip_plus_media_decrypted_pcap)
            if sip_plus_media_decrypted_pcap.exists()
            else None,
        },
        "storage_mode": session.storage_mode,
        "storage_notice": session.storage_notice,
    }


@app.get("/api/files/latest")
def latest_files() -> Dict[str, Any]:
    session = CAPTURE_SERVICE.latest_session()
    if session is None:
        raise HTTPException(status_code=404, detail="No capture session available")
    LOGGER.info("API latest files session_id=%s", session.session_id, extra={"category": "FILES", "correlation_id": session.session_id})

    raw = _raw_file_links(session)
    decrypted = [_file_link(session, "decrypted", path) for path in session.decrypted_dir.glob("*.pcap")]

    raw_dir_value = CAPTURE_SERVICE.storage_target_hint(session)
    storage_mode_value = session.storage_mode
    if session.s3_source_session_prefix:
        source_raw = (
            session.s3_source_session_prefix
            if session.s3_source_session_prefix.endswith("/raw")
            else f"{session.s3_source_session_prefix}/raw"
        )
        raw_dir_value = CAPTURE_SERVICE._s3.format_location(source_raw)  # type: ignore[attr-defined]
        storage_mode_value = "s3"
    return {
        "session_id": session.session_id,
        "raw_dir": raw_dir_value,
        "storage_mode": storage_mode_value,
        "storage_notice": session.storage_notice,
        "storage_target": CAPTURE_SERVICE.storage_target_hint(session),
        "raw": raw,
        "decrypted": sorted(decrypted),
    }


@app.get("/downloads/{session_id}/{kind}/{filename}")
def download_file(session_id: str, kind: str, filename: str) -> FileResponse:
    session = CAPTURE_SERVICE.latest_session()
    if session is None or session.session_id != session_id:
        raise HTTPException(status_code=404, detail="Session not found")

    if kind not in {"raw", "decrypted", "combined"}:
        raise HTTPException(status_code=400, detail="Invalid download kind")

    if kind == "raw":
        base = session.raw_dir
    elif kind == "decrypted":
        base = session.decrypted_dir
    else:
        base = session.base_dir / "combined"
    target = (base / filename).resolve()

    if not str(target).startswith(str(base.resolve())):
        raise HTTPException(status_code=400, detail="Invalid file path")

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    LOGGER.info(
        "Download file session_id=%s kind=%s file=%s",
        session_id,
        kind,
        target,
        extra={"category": "FILES", "correlation_id": session_id},
    )

    return FileResponse(path=target)


def _select_best_call(calls: Dict[str, SipCall]) -> SipCall | None:
    if not calls:
        return None

    def score(call: SipCall) -> tuple[int, int]:
        media_count = len(call.media_sections)
        crypto_count = sum(len(media.sdes_cryptos) for media in call.media_sections)
        return (crypto_count, media_count)

    return sorted(calls.values(), key=score, reverse=True)[0]


def _select_best_call_with_grouping(parsed: Any, direction: str) -> Tuple[SipCall, CorrelationContext, List[str]]:
    """
    Select the best call using multi-Call-ID grouping via X-Talkdesk-Other-Leg-Call-Id.
    
    Returns:
        Tuple of (merged SipCall, CorrelationContext, list of all Call-IDs)
    """
    from rtphelper.services.sip_parser import SipParseResult
    
    if not isinstance(parsed, SipParseResult):
        raise ValueError("Expected SipParseResult")
    
    # Use new correlation service to group and correlate
    ctx, merged_call = correlate_sip_call(parsed, direction)
    
    return merged_call, ctx, ctx.call_ids


def _resolve_negotiation_context(call: SipCall, direction: str) -> Dict[str, Any]:
    invites = [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
    invites.sort(key=lambda m: m.ts)
    if not invites:
        raise ValueError("No INVITE found in SIP pcap")
    invites_with_sdp = [m for m in invites if m.has_sdp and m.media_sections]
    first_inv = invites_with_sdp[0] if invites_with_sdp else invites[0]
    # Use the destination of the last INVITE in the negotiation sequence as last_host.
    # This is the final host targeted by INVITE during negotiation (position-independent).
    last_invite = invites[-1]
    last_host = last_invite.dst_ip or last_invite.src_ip

    if direction == "inbound":
        carrier = first_inv.src_ip
        core = last_host
    elif direction == "outbound":
        core = first_inv.src_ip
        carrier = last_host
    else:
        raise ValueError("Direction must be Inbound or Outbound")

    return {
        "first_invite_source_ip": first_inv.src_ip,
        "first_invite_destination_ip": first_inv.dst_ip,
        "first_invite_packet": first_inv.packet_number,
        "last_negotiation_host_ip": last_host,
        "last_packet_invite": last_invite.packet_number,
        "carrier_ip": carrier,
        "core_ip": core,
    }


def _match_200_ok_for_invite(call: SipCall, invite: SipMessage) -> SipMessage | None:
    candidates = [
        m
        for m in call.messages
        if (not m.is_request)
        and m.status_code == 200
        and m.src_ip == invite.dst_ip
        and m.dst_ip == invite.src_ip
        and m.ts >= invite.ts
        and (m.ts - invite.ts) <= 180.0
    ]
    candidates.sort(key=lambda m: m.ts)

    exact: List[SipMessage] = []
    for m in candidates:
        if invite.cseq_num is not None and m.cseq_num is not None and invite.cseq_num != m.cseq_num:
            continue
        if invite.cseq_method and m.cseq_method and invite.cseq_method != m.cseq_method:
            continue
        if invite.via_branch and m.via_branch and invite.via_branch != m.via_branch:
            continue
        exact.append(m)
    if exact:
        return exact[0]
    if candidates:
        return candidates[0]
    return None


def _next_200ok_same_route_with_audio(call: SipCall, ok: SipMessage) -> SipMessage | None:
    """
    If the selected 200 OK doesn't contain usable m=audio port, try the next 200 OK
    from the same source to the same destination that does.
    """
    if ok is None:
        return None
    candidates = [
        m
        for m in call.messages
        if (not m.is_request)
        and m.status_code == 200
        and m.src_ip == ok.src_ip
        and m.dst_ip == ok.dst_ip
        and m.ts > ok.ts
    ]
    candidates.sort(key=lambda m: m.ts)
    for cand in candidates:
        if _first_audio_port(cand) is not None:
            return cand
    return None


def _select_invite_and_ok_for_direction(call: SipCall, negotiation: Dict[str, Any], direction: str) -> tuple[SipMessage, SipMessage]:
    carrier_ip = negotiation["carrier_ip"]
    last_host = negotiation["last_negotiation_host_ip"]
    invites = [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
    invites.sort(key=lambda m: m.ts)
    if not invites:
        raise ValueError("No INVITE found in SIP pcap")

    if direction == "inbound":
        invite = next((m for m in invites if m.src_ip == carrier_ip), None)
        if invite is None:
            # Strict fallback to first INVITE observed.
            invite = invites[0]
    elif direction == "outbound":
        outbound = [m for m in invites if m.dst_ip == last_host]
        if not outbound:
            raise ValueError(
                "Outbound mode: could not find INVITE sent to last negotiation host "
                f"last_host={last_host} first_invite_packet={invites[0].packet_number}"
            )
        invite = sorted(outbound, key=lambda m: m.ts)[-1]
    else:
        raise ValueError("Direction must be Inbound or Outbound")

    # If selected INVITE has no SDP, try immediate neighbor packets (-1 then +1)
    # and pick an INVITE with SDP from the same call context.
    if not (invite.has_sdp and invite.media_sections):
        adjacent = _adjacent_invite_with_sdp(call, invite)
        if adjacent is not None:
            invite = adjacent

    ok = _match_200_ok_for_invite(call, invite)
    if ok is None:
        raise ValueError("Could not find 200 OK matching selected INVITE")
    if _first_audio_port(ok) is None:
        next_ok = _next_200ok_same_route_with_audio(call, ok)
        if next_ok is not None:
            ok = next_ok
    return invite, ok


def _adjacent_invite_with_sdp(call: SipCall, invite: SipMessage) -> SipMessage | None:
    """
    Fallback for inline selection:
    if selected INVITE has no SDP, check immediate packet neighbors first
    (previous packet has priority, then next packet) for an INVITE with SDP.
    """
    if invite.packet_number is None:
        return None
    by_packet = {m.packet_number: m for m in call.messages if m.packet_number is not None}
    for candidate_packet in (invite.packet_number - 1, invite.packet_number + 1):
        cand = by_packet.get(candidate_packet)
        if cand is None:
            continue
        if not cand.is_request:
            continue
        if (cand.method or "").upper() != "INVITE":
            continue
        if cand.has_sdp and cand.media_sections:
            return cand
    return None


def _first_audio_port(msg: SipMessage) -> int | None:
    for section in msg.media_sections:
        if (section.media_type or "").lower() == "audio" and section.port:
            return int(section.port)
    return None


def _first_audio_ip(msg: SipMessage) -> str | None:
    for section in msg.media_sections:
        if (section.media_type or "").lower() == "audio" and section.connection_ip:
            return str(section.connection_ip)
    return None


def _resolve_carrier_request_reply_ports(call: SipCall, negotiation: Dict[str, Any], direction: str) -> tuple[int, int, str | None, str | None]:
    invite, ok = _select_carrier_request_reply_messages(call, negotiation, direction)
    request_port = _first_audio_port(invite)
    reply_port = _first_audio_port(ok)
    request_ip = _first_audio_ip(invite)
    reply_ip = _first_audio_ip(ok)
    if request_port is None:
        raise ValueError(
            "RTP request port not found in INVITE SDP m=audio "
            f"selected_invite_packet={invite.packet_number} selected_200ok_packet={ok.packet_number}"
        )
    if reply_port is None:
        raise ValueError(
            "RTP reply port not found in 200 OK SDP m=audio "
            f"selected_invite_packet={invite.packet_number} selected_200ok_packet={ok.packet_number}"
        )
    if direction == "outbound":
        # Use carrier media IP from 200 OK c=IN for carrier filters.
        carrier_media_ip = reply_ip
        return request_port, reply_port, carrier_media_ip, carrier_media_ip
    return request_port, reply_port, request_ip, reply_ip


def _select_carrier_request_reply_messages(call: SipCall, negotiation: Dict[str, Any], direction: str) -> tuple[SipMessage, SipMessage]:
    if direction == "outbound":
        # Outbound special rule:
        # 1) Find the last INVITE without To tag.
        # 2) Validate traffic received from that host.
        # 3) Choose the first INVITE sent to that host.
        # 4) Find the corresponding 200 OK.
        # 5) Use c=IN from that 200 OK as carrier RTP IP for filters.
        invites = [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
        invites.sort(key=lambda m: m.ts)
        if not invites:
            raise ValueError("No INVITE found in SIP pcap")

        no_tag_invites = [m for m in invites if not m.to_tag]
        if not no_tag_invites:
            raise ValueError("Could not find INVITE without To tag for outbound carrier RTP IP resolution")
        last_no_tag_invite = sorted(no_tag_invites, key=lambda m: m.ts)[-1]
        target_host = last_no_tag_invite.dst_ip

        received_from_host = [m for m in call.messages if m.src_ip == target_host and m.ts >= last_no_tag_invite.ts]
        if not received_from_host:
            raise ValueError("No messages received from host selected by last INVITE without To tag")

        invites_to_host = [m for m in invites if m.dst_ip == target_host]
        if not invites_to_host:
            raise ValueError(
                "Could not find first INVITE sent to selected host for outbound carrier RTP IP resolution "
                f"target_host={target_host} last_no_tag_packet={last_no_tag_invite.packet_number}"
            )
        invites_to_host.sort(key=lambda m: m.ts)
        invites_to_host_with_sdp = [m for m in invites_to_host if m.has_sdp and m.media_sections]
        invite = invites_to_host_with_sdp[0] if invites_to_host_with_sdp else invites_to_host[0]

        ok = _match_200_ok_for_invite(call, invite)
        if ok is None:
            raise ValueError("Could not find 200 OK corresponding to first INVITE sent to selected host")
    else:
        invite, ok = _select_invite_and_ok_for_direction(call, negotiation, direction)
    if _first_audio_port(ok) is None:
        next_ok = _next_200ok_same_route_with_audio(call, ok)
        if next_ok is not None:
            ok = next_ok
    return invite, ok


def _resolve_core_request_reply_ports(call: SipCall, negotiation: Dict[str, Any], direction: str) -> tuple[int, int, str | None, str | None]:
    invite, ok = _select_core_request_reply_messages(call, negotiation, direction)
    request_port = _first_audio_port(invite)
    reply_port = _first_audio_port(ok)
    request_ip = _first_audio_ip(invite)
    reply_ip = _first_audio_ip(ok)
    if request_port is None:
        raise ValueError(
            "Host-core request RTP port not found in INVITE SDP m=audio "
            f"selected_invite_packet={invite.packet_number} selected_200ok_packet={ok.packet_number}"
        )
    if reply_port is None:
        raise ValueError(
            "Host-core reply RTP port not found in 200 OK SDP m=audio "
            f"selected_invite_packet={invite.packet_number} selected_200ok_packet={ok.packet_number}"
        )
    return request_port, reply_port, request_ip, reply_ip


def _select_core_request_reply_messages(call: SipCall, negotiation: Dict[str, Any], direction: str) -> tuple[SipMessage, SipMessage]:
    """
    Host<->Core RTP ports from SIP m=audio:
    - Outbound: request/reply from first INVITE + matching 200 OK
    - Inbound: request/reply from INVITE sent to LastNegotiationHostIP + matching 200 OK
    """
    invites = [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
    invites.sort(key=lambda m: m.ts)
    if not invites:
        raise ValueError("No INVITE found in SIP pcap")

    if direction == "outbound":
        invites_with_sdp = [m for m in invites if m.has_sdp and m.media_sections]
        invite = invites_with_sdp[0] if invites_with_sdp else invites[0]
    elif direction == "inbound":
        last_host = negotiation["last_negotiation_host_ip"]
        cand = [m for m in invites if m.dst_ip == last_host]
        if not cand:
            raise ValueError("Inbound mode: could not find INVITE sent to last negotiation host")
        invite = sorted(cand, key=lambda m: m.ts)[-1]
    else:
        raise ValueError("Direction must be Inbound or Outbound")

    ok = _match_200_ok_for_invite(call, invite)
    if ok is None:
        raise ValueError("Could not find 200 OK for host-core INVITE")
    if _first_audio_port(ok) is None:
        next_ok = _next_200ok_same_route_with_audio(call, ok)
        if next_ok is not None:
            ok = next_ok
    return invite, ok


def _collect_sdes_materials(msg: SipMessage) -> List[SdesCryptoMaterial]:
    out: List[SdesCryptoMaterial] = []
    for section in msg.media_sections:
        for c in section.sdes_cryptos:
            out.append(c)
    return out


def _message_by_packet(call: SipCall, packet_number: int) -> SipMessage | None:
    for msg in call.messages:
        if msg.packet_number == packet_number:
            return msg
    return None


def _select_inline_crypto_for_packet_pair(
    call: SipCall,
    invite_packet_number: int,
    ok_packet_number: int,
) -> List[SdesCryptoMaterial]:
    """Select invite/reply SDES materials from explicit packet numbers."""
    invite = _message_by_packet(call, invite_packet_number)
    ok = _message_by_packet(call, ok_packet_number)
    if invite is None or ok is None:
        raise ValueError("Missing INVITE/200 OK packets for selected cipher pair")

    invite_cryptos = _collect_sdes_materials(invite)
    ok_cryptos = _collect_sdes_materials(ok)
    if not invite_cryptos or not ok_cryptos:
        raise ValueError("Missing SDES inline values in INVITE/200 OK for selected packet pair")

    invite_by_suite: Dict[str, SdesCryptoMaterial] = {}
    for c in invite_cryptos:
        invite_by_suite.setdefault(c.suite, c)
    common = [c for c in ok_cryptos if c.suite in invite_by_suite]
    if not common:
        raise ValueError("No common crypto suite between INVITE and 200 OK for selected packet pair")
    selected_ok = common[0]
    selected_invite = invite_by_suite[selected_ok.suite]
    return [selected_invite, selected_ok]


def _inline_from_material(material: SdesCryptoMaterial) -> str:
    raw = material.master_key + material.master_salt
    return base64.b64encode(raw).decode("ascii")


def _selected_crypto_log_lines(
    selected_crypto: List[SdesCryptoMaterial],
    direction: str,
    request_packet_number: int | None = None,
    reply_packet_number: int | None = None,
) -> List[str]:
    labels = ["request", "reply"]
    lines: List[str] = []
    for idx, material in enumerate(selected_crypto):
        role = labels[idx] if idx < len(labels) else f"material_{idx + 1}"
        packet_number = request_packet_number if role == "request" else reply_packet_number if role == "reply" else None
        packet_fragment = f" packet_number={packet_number}" if packet_number is not None else ""
        lines.append(
            f"direction={direction} role={role} suite={material.suite} inline={_inline_from_material(material)}{packet_fragment}"
        )
    return lines


def _select_inline_crypto_for_direction(call: SipCall, negotiation: Dict[str, str], direction: str) -> List[SdesCryptoMaterial]:
    """
    Select two independent inline values (request and reply) using suite intersection:
    - Inbound: first INVITE from Carrier + its 200 OK
    - Outbound: last INVITE to LastNegotiationHostIP + its 200 OK
    """
    invite, ok = _select_invite_and_ok_for_direction(call, negotiation, direction)

    invite_cryptos = _collect_sdes_materials(invite)
    ok_cryptos = _collect_sdes_materials(ok)
    if not invite_cryptos or not ok_cryptos:
        raise ValueError("Missing SDES inline values in INVITE/200 OK for selected direction")

    invite_by_suite: Dict[str, SdesCryptoMaterial] = {}
    for c in invite_cryptos:
        invite_by_suite.setdefault(c.suite, c)
    ok_by_suite_ordered: List[SdesCryptoMaterial] = ok_cryptos

    common = [c for c in ok_by_suite_ordered if c.suite in invite_by_suite]
    if not common:
        raise ValueError("No common crypto suite between INVITE and 200 OK; cannot select inline values")

    # If multiple, select first common suite in 200 OK order.
    selected_ok = common[0]
    selected_invite = invite_by_suite[selected_ok.suite]
    return [selected_invite, selected_ok]


def _is_media_encrypted_expected(call: SipCall, direction: str, negotiation: Dict[str, str]) -> tuple[bool, List[str]]:
    """
    Confirm whether media is expected to be encrypted by inspecting SDP in the INVITE/200 OK pair
    selected for the given direction.
    """
    invite, ok = _select_invite_and_ok_for_direction(call, negotiation, direction)
    reasons: List[str] = []
    explicit_plain_reasons: List[str] = []
    for msg, side in [(invite, "invite"), (ok, "200ok")]:
        for section in msg.media_sections:
            proto = (section.protocol or "").upper()
            if "SAVP" in proto:
                reasons.append(f"{side}:protocol={proto}")
            elif proto == "RTP/AVP":
                explicit_plain_reasons.append(f"{side}:protocol={proto}")
            if section.sdes_cryptos:
                reasons.append(f"{side}:sdes={len(section.sdes_cryptos)}")
            if section.dtls_fingerprints:
                reasons.append(f"{side}:dtls_fp={len(section.dtls_fingerprints)}")
            if section.dtls_exporter_key:
                reasons.append(f"{side}:dtls_exporter_key=1")

    carrier_200ok_proto = _carrier_received_200ok_audio_proto(call, negotiation)
    if carrier_200ok_proto:
        carrier_proto_upper = carrier_200ok_proto.upper()
        if "SAVP" in carrier_proto_upper:
            reasons.append(f"carrier_received_200ok:protocol={carrier_proto_upper}")
        elif carrier_proto_upper == "RTP/AVP":
            explicit_plain_reasons.append(f"carrier_received_200ok:protocol={carrier_proto_upper}")

    # Encrypted markers have precedence. If none found but explicit AVP is present, mark as non-encrypted.
    if reasons:
        return True, reasons + explicit_plain_reasons
    if explicit_plain_reasons:
        return False, explicit_plain_reasons
    return False, []


def _carrier_received_200ok_audio_proto(call: SipCall, negotiation: Dict[str, str]) -> str | None:
    """
    Find an SDP protocol from m=audio in a 200 OK message received by carrier (dst_ip == carrier_ip).
    Returns protocol like RTP/AVP or RTP/SAVP when found.
    """
    carrier_ip = str(negotiation.get("carrier_ip") or "")
    if not carrier_ip:
        return None
    candidates = [
        m
        for m in call.messages
        if (not m.is_request) and m.status_code == 200 and m.dst_ip == carrier_ip and m.media_sections
    ]
    candidates.sort(key=lambda m: m.ts)
    for msg in candidates:
        for section in msg.media_sections:
            if (section.media_type or "").lower() == "audio" and section.protocol:
                return str(section.protocol)
    return None


def _build_manual_rtp_steps(
    *,
    direction: str,
    carrier_request_ip: str,
    carrier_reply_ip: str,
    carrier_request_port: int,
    carrier_reply_port: int,
    core_request_port: int,
    core_request_ip: str,
    core_reply_ip: str,
    core_reply_port: int,
) -> tuple[List[Dict[str, object]], List[str]]:
    def _format_filter_line(leg_key: str, filter_expr: str) -> str:
        leg_alias = {
            "leg_carrier_rtpengine": "carrier-rtpengine",
            "leg_rtpengine_carrier": "rtpengine-carrier",
            "leg_rtpengine_core": "rtpengine-core",
            "leg_core_rtpengine": "core-rtpengine",
        }.get(leg_key, leg_key)
        stream_hint = {
            "leg_carrier_rtpengine": "media_stream_from_carrier_to_rtpengine",
            "leg_rtpengine_carrier": "media_stream_from_rtpengine_to_carrier",
            "leg_rtpengine_core": "media_stream_from_rtpengine_to_core",
            "leg_core_rtpengine": "media_stream_from_core_to_rtpengine",
        }.get(leg_key, "media_stream_unknown")
        return f"[{leg_alias}] FILTER: \"{filter_expr}\" [{stream_hint}]"

    steps: List[Dict[str, object]] = []
    debug: List[str] = []
    carrier_request_ip = str(carrier_request_ip or "").strip()
    carrier_reply_ip = str(carrier_reply_ip or "").strip()
    carrier_port = carrier_request_port
    core_request_ip = str(core_request_ip or "").strip()
    core_reply_ip = str(core_reply_ip or "").strip()
    core_port = core_reply_port
    host_carrier_port = carrier_request_port
    host_core_port = core_request_port

    if direction == "outbound":
        # Outbound override requested:
        # Step 3: udp.srcport == step4-port (core_reply_port), ip.dst == step4-ip (core_request_ip)
        # Step 4: ip.src == same core_request_ip, udp.port == step3-port (core_request_port)
        host_core_port = core_reply_port
        core_port = core_request_port

    # Step 1: carrier -> host
    # Expected filter mapping:
    #   ip.src == carrier_ip_from_200ok_cIN
    #   udp.port == carrier_reply_port
    if not carrier_request_ip or carrier_reply_port is None:
        steps.append(
            {
                "step": 1,
                "leg": "carrier->host",
                "leg_key": "leg_carrier_rtpengine",
                "available": False,
                "from_host": carrier_request_ip or None,
                "from_port": carrier_port,
                "match_type": "src_host_port",
                "tshark_filter": None,
                "reason": "missing or invalid user input",
            }
        )
        debug.append("Step 1 (carrier->host): unavailable - missing or invalid user input")
    else:
        steps.append(
            {
                "step": 1,
                "leg": "carrier->host",
                "leg_key": "leg_carrier_rtpengine",
                "available": True,
                "from_host": carrier_request_ip,
                "from_port": carrier_port,
                "match_type": "src_host_port",
                "tshark_filter": f"ip.src=={carrier_request_ip} && udp.port=={carrier_reply_port}",
                "reason": None,
            }
        )
        debug.append(_format_filter_line("leg_carrier_rtpengine", f"ip.src=={carrier_request_ip} && udp.port=={carrier_reply_port}"))

    # Step 2: host -> carrier
    # Expected filter mapping:
    #   udp.srcport == carrier_request_port
    #   ip.dst == carrier_ip_from_200ok_cIN
    if host_carrier_port is None or not carrier_request_ip:
        steps.append(
            {
                "step": 2,
                "leg": "host->carrier",
                "leg_key": "leg_rtpengine_carrier",
                "available": False,
                "from_host": None,
                "from_port": host_carrier_port,
                "dst_ip": carrier_request_ip or None,
                "match_type": "udp_port_dst_ip",
                "tshark_filter": None,
                "reason": "missing or invalid user input",
            }
        )
        debug.append("Step 2 (host->carrier): unavailable - missing or invalid user input")
    else:
        steps.append(
            {
                "step": 2,
                "leg": "host->carrier",
                "leg_key": "leg_rtpengine_carrier",
                "available": True,
                "from_host": None,
                "from_port": host_carrier_port,
                "dst_ip": carrier_request_ip,
                "match_type": "udp_port_dst_ip",
                "tshark_filter": (
                    f"udp.srcport=={host_carrier_port} && ip.dst=={carrier_request_ip}"
                    if direction == "outbound"
                    else f"udp.port=={host_carrier_port} && ip.dst=={carrier_request_ip}"
                ),
                "reason": None,
            }
        )
        if direction == "outbound":
            debug.append(_format_filter_line("leg_rtpengine_carrier", f"udp.srcport=={host_carrier_port} && ip.dst=={carrier_request_ip}"))
        else:
            debug.append(_format_filter_line("leg_rtpengine_carrier", f"udp.port=={host_carrier_port} && ip.dst=={carrier_request_ip}"))

    # Step 3: host -> core (udp.port + dst.ip from core->host ip)
    core_dst_ip_for_step3 = core_request_ip if direction == "outbound" else core_reply_ip
    if host_core_port is None or not core_dst_ip_for_step3:
        steps.append(
            {
                "step": 3,
                "leg": "host->core",
                "leg_key": "leg_rtpengine_core",
                "available": False,
                "from_host": None,
                "from_port": host_core_port,
                "dst_ip": core_dst_ip_for_step3 or None,
                "match_type": "udp_port_dst_ip",
                "tshark_filter": None,
                "reason": "missing or invalid user input",
            }
        )
        debug.append("Step 3 (host->core): unavailable - missing or invalid user input")
    else:
        steps.append(
            {
                "step": 3,
                "leg": "host->core",
                "leg_key": "leg_rtpengine_core",
                "available": True,
                "from_host": None,
                "from_port": host_core_port,
                "dst_ip": core_dst_ip_for_step3,
                "match_type": "udp_port_dst_ip",
                "tshark_filter": (
                    f"udp.srcport=={host_core_port} && ip.dst=={core_dst_ip_for_step3}"
                    if direction == "outbound"
                    else f"udp.port=={host_core_port} && ip.dst=={core_dst_ip_for_step3}"
                ),
                "reason": None,
            }
        )
        if direction == "outbound":
            debug.append(_format_filter_line("leg_rtpengine_core", f"udp.srcport=={host_core_port} && ip.dst=={core_dst_ip_for_step3}"))
        else:
            debug.append(_format_filter_line("leg_rtpengine_core", f"udp.port=={host_core_port} && ip.dst=={core_dst_ip_for_step3}"))

    # Step 4: core -> host (host + src port style)
    step4_src_ip = core_request_ip if direction == "outbound" else core_reply_ip
    if not step4_src_ip or core_port is None:
        steps.append(
            {
                "step": 4,
                "leg": "core->host",
                "leg_key": "leg_core_rtpengine",
                "available": False,
                "from_host": step4_src_ip or None,
                "from_port": core_port,
                "match_type": "src_host_port",
                "tshark_filter": None,
                "reason": "missing or invalid user input",
            }
        )
        debug.append("Step 4 (core->host): unavailable - missing or invalid user input")
    else:
        steps.append(
            {
                "step": 4,
                "leg": "core->host",
                "leg_key": "leg_core_rtpengine",
                "available": True,
                "from_host": step4_src_ip,
                "from_port": core_port,
                "match_type": "src_host_port",
                "tshark_filter": (
                    f"ip.src=={step4_src_ip} && udp.port=={core_port}"
                    if direction == "outbound"
                    else f"ip.src=={step4_src_ip} && udp.port=={core_port}"
                ),
                "reason": None,
            }
        )
        if direction == "outbound":
            debug.append(_format_filter_line("leg_core_rtpengine", f"ip.src=={step4_src_ip} && udp.port=={core_port}"))
        else:
            debug.append(_format_filter_line("leg_core_rtpengine", f"ip.src=={step4_src_ip} && udp.port=={core_port}"))

    return steps, debug


def _detected_leg_details(
    negotiation: Dict[str, str],
    carrier_request_ip: str | None,
    carrier_reply_ip: str | None,
    carrier_request_port: int,
    carrier_reply_port: int,
    core_request_ip: str | None,
    core_reply_ip: str | None,
    core_request_port: int,
    core_reply_port: int,
) -> Dict[str, Dict[str, object]]:
    carrier_req_ip = str(carrier_request_ip or negotiation["carrier_ip"])
    carrier_rep_ip = str(carrier_reply_ip or negotiation["carrier_ip"])
    core_req_ip = str(core_request_ip or negotiation["core_ip"])
    core_rep_ip = str(core_reply_ip or negotiation["core_ip"])
    return {
        "carrier_host": {"ip": carrier_req_ip, "request_port": carrier_request_port, "reply_port": carrier_reply_port},
        "host_carrier": {"ip": carrier_rep_ip, "request_port": carrier_request_port, "reply_port": carrier_reply_port},
        "host_core": {"ip": core_rep_ip, "request_port": core_request_port, "reply_port": core_reply_port},
        "core_host": {"ip": core_req_ip, "request_port": core_request_port, "reply_port": core_reply_port},
    }


def _extract_rtp_engine_instance(filename: str) -> Optional[str]:
    """
    Extract RTP Engine instance identifier from filename including region.
    
    Examples:
        us-east-1-prd-us-east-1-rtp-1-0001.pcap -> "us-east-1:rtp-1"
        us-west-2-prd-us-east-1-rtp-2-0123.pcap -> "us-west-2:rtp-2"
        eu-west-1-prd-eu-west-1-rtp-3-0001.pcap -> "eu-west-1:rtp-3"
        some-other-file.pcap -> None
        
    Returns:
        The RTP Engine instance identifier with region (e.g., "us-east-1:rtp-1") or None
    """
    import re
    # Match pattern: {region}-prd-{anything}-rtp-{number}
    # Captures region at start and rtp-{number} pattern
    pattern = r'^([a-z]+-[a-z]+-\d+)-prd-.*?(rtp-\d+)'
    match = re.search(pattern, filename, re.IGNORECASE)
    if match:
        region = match.group(1).lower()
        rtp_instance = match.group(2).lower()
        return f"{region}:{rtp_instance}"
    return None


def _group_pcaps_by_rtp_instance(pcap_files: List[Path]) -> Dict[Optional[str], List[Path]]:
    """
    Group PCAP files by RTP Engine instance identifier.
    
    Returns:
        Dictionary mapping instance_id -> list of PCAP files
        Files without identifiable instance go under None key
    """
    from collections import defaultdict
    groups: Dict[Optional[str], List[Path]] = defaultdict(list)
    
    for pcap_file in pcap_files:
        instance_id = _extract_rtp_engine_instance(pcap_file.name)
        groups[instance_id].append(pcap_file)
    
    return dict(groups)


def _materialize_media_pcaps_for_correlation(session: CaptureSession, correlation_id: str, log_lines: List[str]) -> List[Path]:
    local_files = [p for files in session.host_files.values() for p in files if p.exists()]
    if local_files:
        log_lines.append(f"INFO: Using {len(local_files)} local media file(s) already available.")
        return local_files
    if not session.s3_source_objects:
        return []
    total_files = sum(len(v) for v in session.s3_source_objects.values())
    log_lines.append(f"== Step 3.1: Materialize media from S3 ({total_files} file(s)) ==")
    cache_dir = session.base_dir / "s3_source_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    materialized: List[Path] = []
    file_index = 0
    phase_started = time.monotonic()
    for host_id, keys in sorted(session.s3_source_objects.items()):
        for key in keys:
            file_index += 1
            base_name = Path(str(key)).name
            target = cache_dir / base_name
            if target.exists():
                stem = target.stem
                suffix = target.suffix
                i = 1
                while True:
                    cand = cache_dir / f"{stem}__{i}{suffix}"
                    if not cand.exists():
                        target = cand
                        break
                    i += 1
            try:
                log_lines.append(
                    f"INFO: S3 media file start {file_index}/{total_files} host={host_id} file={base_name}"
                )
                _run_with_heartbeat(
                    run=lambda: CAPTURE_SERVICE._s3.download_key_to_file(str(key), target),  # type: ignore[attr-defined]
                    heartbeat_message=lambda elapsed_s: (
                        "INFO: S3 download in progress "
                        f"file={file_index}/{total_files} host={host_id} file={base_name} elapsed={elapsed_s:.0f}s"
                    ),
                )
                materialized.append(target)
                log_lines.append(
                    f"INFO: S3 media file ready {file_index}/{total_files} host={host_id} file={base_name}"
                )
                LOGGER.info(
                    "Correlation source materialized from S3 host=%s key=%s local=%s",
                    host_id,
                    key,
                    target,
                    extra={"category": "FILES", "correlation_id": correlation_id},
                )
            except Exception as exc:
                log_lines.append(f"WARN: Could not read S3 media file host={host_id} key={key} reason={exc}")
                LOGGER.warning(
                    "Could not materialize correlation source from S3 host=%s key=%s reason=%s",
                    host_id,
                    key,
                    exc,
                    extra={"category": "FILES", "correlation_id": correlation_id},
                )
    phase_elapsed = time.monotonic() - phase_started
    log_lines.append(
        f"INFO: S3 media materialization finished files_ready={len(materialized)}/{total_files} "
        f"duration={phase_elapsed:.1f}s"
    )
    return materialized


def _run_with_heartbeat(
    run,
    heartbeat_message,
    interval_seconds: float = CORRELATION_HEARTBEAT_SECONDS,
):
    done = threading.Event()
    outcome: Dict[str, Any] = {}

    def _target() -> None:
        try:
            outcome["result"] = run()
        except Exception as exc:
            outcome["error"] = exc
        finally:
            done.set()

    worker = threading.Thread(target=_target, name="correlation-heartbeat-task", daemon=True)
    worker.start()
    started = time.monotonic()
    next_beat = started + max(1.0, float(interval_seconds))
    while not done.wait(timeout=0.5):
        now = time.monotonic()
        if now >= next_beat:
            elapsed = max(0.0, now - started)
            try:
                msg = str(heartbeat_message(elapsed))
            except Exception:
                msg = f"INFO: Correlation task still running elapsed={elapsed:.0f}s"
            LOGGER.info(msg, extra={"category": "RTP_SEARCH"})
            next_beat = now + max(1.0, float(interval_seconds))
    worker.join(timeout=0.2)
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


def _process_single_pcap_with_filter(
    pcap_file: Path,
    pcap_idx: int,
    total_pcaps: int,
    instance_id: Optional[str],
    rtpengine_actual_ip: Optional[str],
    correlation_ctx: Optional[CorrelationContext],
    filtered_dir: Path,
    call_cid: str,
) -> Dict[str, Any]:
    """
    Process a single PCAP file with filters in parallel.
    Thread-safe function that builds filters, counts packets, and writes filtered output.
    
    Returns:
        Dictionary with processing results for aggregation
    """
    try:
        # Build filters for this specific instance
        if correlation_ctx:
            steps = build_tshark_filters(correlation_ctx, rtpengine_actual_ip)
        else:
            steps = []
        
        # Collect available filters for this file
        available_filters: List[Tuple[int, str, str]] = []
        for step in steps:
            step_num = int(step["step"])
            leg_key = str(step["leg_key"])
            available = bool(step["available"])
            filter_expr = str(step.get("tshark_filter") or "")
            if available and filter_expr:
                available_filters.append((step_num, leg_key, filter_expr))
        
        if not available_filters:
            return {
                "status": "skipped",
                "reason": "no_filters",
                "file": pcap_file,
                "instance_id": instance_id,
                "packets": 0,
            }
        
        # Combine filters with OR
        combined_filter = " || ".join(f"({filter_expr})" for _, _, filter_expr in available_filters)
        
        # Count matching packets
        pkt_count = _tshark_count_matches(pcap_file, combined_filter, call_cid)
        
        if pkt_count <= 1:
            return {
                "status": "skipped",
                "reason": "no_packets",
                "file": pcap_file,
                "instance_id": instance_id,
                "packets": pkt_count,
                "filter": combined_filter,
            }
        
        # Write filtered PCAP
        out_file = filtered_dir / f"combined-or-{pcap_file.stem}-filtered.pcap"
        _tshark_write_filtered(pcap_file, combined_filter, out_file, call_cid)
        
        return {
            "status": "success",
            "file": pcap_file,
            "output": out_file,
            "instance_id": instance_id,
            "packets": pkt_count,
            "filter": combined_filter,
        }
        
    except Exception as exc:
        return {
            "status": "error",
            "file": pcap_file,
            "instance_id": instance_id,
            "error": str(exc),
        }


def _tshark_count_matches(pcap_file: Path, filter_expr: str, correlation_id: str) -> int:
    cmd = (
        f"tshark -r {shlex.quote(str(pcap_file))} "
        f"-Y {shlex.quote(filter_expr)} 2>/dev/null | wc -l"
    )
    LOGGER.debug(
        "Running tshark count command=%s",
        cmd,
        extra={"category": "RTP_SEARCH", "correlation_id": correlation_id},
    )
    proc = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "tshark count failed").strip())
    raw = (proc.stdout or "").strip()
    try:
        return int(raw or "0")
    except ValueError:
        raise RuntimeError(f"Unexpected tshark count output: {raw}") from None


def _tshark_write_filtered(pcap_file: Path, filter_expr: str, out_file: Path, correlation_id: str) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "tshark",
        "-r",
        str(pcap_file),
        "-Y",
        filter_expr,
        "-w",
        str(out_file),
    ]
    LOGGER.debug(
        "Running tshark write command=%s",
        cmd,
        extra={"category": "RTP_SEARCH", "correlation_id": correlation_id},
    )
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "tshark write failed").strip())


def _detect_encrypted_filtered_file(filtered_pcap: Path, *, default_encrypted: bool, correlation_id: str) -> bool:
    """
    Best-effort per-file encryption detection:
    - if SRTP packets detected -> encrypted
    - if RTP packets detected and no SRTP -> not encrypted
    - otherwise fallback to call-level default_encrypted
    """
    try:
        srtp_count = _tshark_count_matches(filtered_pcap, "srtp", correlation_id)
    except Exception:
        srtp_count = 0
    if srtp_count > 0:
        return True
    try:
        rtp_count = _tshark_count_matches(filtered_pcap, "rtp", correlation_id)
    except Exception:
        rtp_count = 0
    if rtp_count > 0:
        # RTP dissector can classify SRTP as RTP. When SIP-side expectation is encrypted,
        # keep encrypted=True instead of trusting dissector-only RTP classification.
        return default_encrypted
    return default_encrypted


_IMPORT_NAME_RE = re.compile(r"^(?P<prefix>.+)-(?P<seq>\d{4})\.(pcap|pcapng)$", flags=re.IGNORECASE)


def _host_key_from_capture_filename(filename: str) -> str:
    """
    Best-effort: infer a "host key" from a rolling capture name like:
      <region>-<host>-0001.pcap

    For imported captures we keep the full prefix (region-host) as the host key.
    """
    name = Path(filename).name
    match = _IMPORT_NAME_RE.match(name)
    if not match:
        return "imported"
    prefix = match.group("prefix")
    return prefix or "imported"


def _file_link(session, kind: str, path: Path) -> str:
    remote = CAPTURE_SERVICE.file_reference(session, path)
    if remote:
        return remote
    return f"/downloads/{session.session_id}/{kind}/{path.name}"


def _cleanup_local_raw_after_postprocess(session: CaptureSession, log_lines: List[str], correlation_id: str) -> None:
    # Never remove user-provided raw directories from local-reference imports.
    if str(getattr(session, "source_mode", "") or "") == "local_reference":
        return
    if not bool(getattr(session, "raw_dir_managed", True)):
        return
    raw_dir = session.raw_dir
    if not raw_dir.exists():
        return
    try:
        removed_files = sum(1 for p in raw_dir.rglob("*") if p.is_file())
        shutil.rmtree(raw_dir)
        session.host_files = {}
        session.host_packet_counts = {}
        msg = (
            f"Local raw media directory removed after post-process dir={raw_dir} "
            f"files_removed={removed_files}"
        )
        log_lines.append(f"INFO: {msg}")
        LOGGER.info(msg, extra={"category": "FILES", "correlation_id": correlation_id})
    except Exception as exc:
        msg = f"Could not remove local raw media directory after post-process dir={raw_dir} reason={exc}"
        log_lines.append(f"WARN: {msg}")
        LOGGER.warning(msg, extra={"category": "FILES", "correlation_id": correlation_id})


def _raw_file_links(session) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if session.s3_source_objects:
        for host, keys in session.s3_source_objects.items():
            links: List[str] = []
            for key in keys:
                try:
                    links.append(CAPTURE_SERVICE._s3.format_key_location(str(key)))  # type: ignore[attr-defined]
                except Exception:
                    continue
            if links:
                out[host] = links
        if out:
            return out
    for host, files in session.host_files.items():
        links: List[str] = []
        for path in files:
            remote = CAPTURE_SERVICE.file_reference(session, path)
            if remote:
                links.append(remote)
                continue
            if path.exists():
                links.append(f"/downloads/{session.session_id}/raw/{path.name}")
        if links:
            out[host] = links
    return out


def _project_log_files() -> List[Path]:
    files: List[Path] = []
    log_dir = LOG_FILE.parent
    if not log_dir.exists():
        return files
    exclude_names = {"access.log"}
    for path in sorted(log_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name in exclude_names:
            continue
        if name.endswith(".log") or ".log." in name or name.endswith(".txt"):
            files.append(path)
    return files
