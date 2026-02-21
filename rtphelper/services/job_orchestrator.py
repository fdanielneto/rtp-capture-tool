from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class JobEvent:
    seq: int
    ts: float
    level: str
    message: str
    step: str = ""


@dataclass
class JobRecord:
    job_id: str
    job_type: str
    status: str
    payload: Dict[str, Any]
    created_at: float
    updated_at: float
    started_at: float | None = None
    finished_at: float | None = None
    progress_step: str = ""
    error: str | None = None
    result: Dict[str, Any] | None = None
    events: List[JobEvent] | None = None


class JobOrchestrator:
    def __init__(self, db_path: Path, max_queue_size: int = 256) -> None:
        self._db_path = Path(db_path)
        self._max_queue_size = max(1, int(max_queue_size))
        self._lock = threading.Lock()
        self._event_cond = threading.Condition(self._lock)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    job_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    started_at REAL,
                    finished_at REAL,
                    progress_step TEXT NOT NULL DEFAULT '',
                    error_text TEXT,
                    result_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS job_events (
                    job_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    ts REAL NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    step TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (job_id, seq)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_job_seq ON job_events(job_id, seq)")
            conn.commit()

    def submit(self, job_type: str, payload: Dict[str, Any]) -> JobRecord:
        with self._connect() as conn:
            queued = conn.execute("SELECT COUNT(1) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]
            if int(queued or 0) >= self._max_queue_size:
                raise RuntimeError("Job queue is full")
            now = time.time()
            job_id = uuid.uuid4().hex
            conn.execute(
                """
                INSERT INTO jobs(job_id, job_type, status, payload_json, created_at, updated_at, progress_step)
                VALUES (?, ?, 'queued', ?, ?, ?, 'queued')
                """,
                (job_id, str(job_type), json.dumps(payload), now, now),
            )
            conn.execute(
                """
                INSERT INTO job_events(job_id, seq, ts, level, message, step)
                VALUES (?, 1, ?, 'info', 'Job queued', 'queued')
                """,
                (job_id, now),
            )
            conn.commit()
        with self._event_cond:
            self._event_cond.notify_all()
        return JobRecord(
            job_id=job_id,
            job_type=str(job_type),
            status="queued",
            payload=dict(payload),
            created_at=now,
            updated_at=now,
            progress_step="queued",
            events=[JobEvent(seq=1, ts=now, level="info", message="Job queued", step="queued")],
        )

    def get(self, job_id: str) -> Optional[JobRecord]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return None
            return self._job_from_row(conn, row, include_events=True)

    def list_events(self, job_id: str, after_seq: int = 0) -> List[JobEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, ts, level, message, step FROM job_events WHERE job_id = ? AND seq > ? ORDER BY seq ASC",
                (job_id, int(after_seq)),
            ).fetchall()
        return [
            JobEvent(
                seq=int(r["seq"]),
                ts=float(r["ts"]),
                level=str(r["level"]),
                message=str(r["message"]),
                step=str(r["step"] or ""),
            )
            for r in rows
        ]

    def wait_for_events(self, job_id: str, after_seq: int = 0, timeout: float = 10.0) -> List[JobEvent]:
        deadline = time.time() + max(0.1, timeout)
        while True:
            events = self.list_events(job_id, after_seq=after_seq)
            if events:
                return events
            remain = deadline - time.time()
            if remain <= 0:
                return []
            with self._event_cond:
                self._event_cond.wait(timeout=remain)

    def next_job_id(self, timeout: float = 0.5) -> str | None:
        deadline = time.time() + max(0.1, timeout)
        while True:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT job_id FROM jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
                ).fetchone()
                if row:
                    return str(row["job_id"])
            remain = deadline - time.time()
            if remain <= 0:
                return None
            with self._event_cond:
                self._event_cond.wait(timeout=min(0.25, remain))

    def mark_running(self, job_id: str, step: str = "running") -> None:
        self._update_job_status(job_id, status="running", step=step, add_event=("info", "Job started", step), set_started=True)

    def progress(self, job_id: str, message: str, step: str = "running", level: str = "info") -> None:
        with self._connect() as conn:
            now = time.time()
            conn.execute(
                "UPDATE jobs SET updated_at = ?, progress_step = ? WHERE job_id = ?",
                (now, str(step), job_id),
            )
            self._append_event(conn, job_id, level=str(level), message=str(message), step=str(step), ts=now)
            conn.commit()
        with self._event_cond:
            self._event_cond.notify_all()

    def complete(self, job_id: str, result: Dict[str, Any]) -> None:
        with self._connect() as conn:
            now = time.time()
            conn.execute(
                """
                UPDATE jobs
                SET status = 'completed', updated_at = ?, finished_at = ?, progress_step = 'completed', result_json = ?, error_text = NULL
                WHERE job_id = ?
                """,
                (now, now, json.dumps(result or {}), job_id),
            )
            self._append_event(conn, job_id, level="info", message="Job completed", step="completed", ts=now)
            conn.commit()
        with self._event_cond:
            self._event_cond.notify_all()

    def fail(self, job_id: str, error: str, result: Dict[str, Any] | None = None) -> None:
        with self._connect() as conn:
            now = time.time()
            conn.execute(
                """
                UPDATE jobs
                SET status = 'failed', updated_at = ?, finished_at = ?, progress_step = 'failed', error_text = ?, result_json = COALESCE(?, result_json)
                WHERE job_id = ?
                """,
                (now, now, str(error), json.dumps(result) if result is not None else None, job_id),
            )
            self._append_event(conn, job_id, level="error", message=str(error), step="failed", ts=now)
            conn.commit()
        with self._event_cond:
            self._event_cond.notify_all()

    def _update_job_status(
        self,
        job_id: str,
        status: str,
        step: str,
        add_event: tuple[str, str, str] | None = None,
        set_started: bool = False,
    ) -> None:
        with self._connect() as conn:
            now = time.time()
            if set_started:
                conn.execute(
                    "UPDATE jobs SET status = ?, updated_at = ?, started_at = COALESCE(started_at, ?), progress_step = ? WHERE job_id = ?",
                    (str(status), now, now, str(step), job_id),
                )
            else:
                conn.execute(
                    "UPDATE jobs SET status = ?, updated_at = ?, progress_step = ? WHERE job_id = ?",
                    (str(status), now, str(step), job_id),
                )
            if add_event:
                self._append_event(conn, job_id, level=add_event[0], message=add_event[1], step=add_event[2], ts=now)
            conn.commit()
        with self._event_cond:
            self._event_cond.notify_all()

    def _append_event(self, conn: sqlite3.Connection, job_id: str, level: str, message: str, step: str, ts: float) -> None:
        row = conn.execute("SELECT COALESCE(MAX(seq), 0) AS last_seq FROM job_events WHERE job_id = ?", (job_id,)).fetchone()
        seq = int(row["last_seq"] or 0) + 1
        conn.execute(
            "INSERT INTO job_events(job_id, seq, ts, level, message, step) VALUES (?, ?, ?, ?, ?, ?)",
            (job_id, seq, float(ts), str(level), str(message), str(step)),
        )

    def _job_from_row(self, conn: sqlite3.Connection, row: sqlite3.Row, include_events: bool) -> JobRecord:
        payload = self._json_or_default(row["payload_json"], {})
        result = self._json_or_default(row["result_json"], None)
        events: List[JobEvent] | None = None
        if include_events:
            ev_rows = conn.execute(
                "SELECT seq, ts, level, message, step FROM job_events WHERE job_id = ? ORDER BY seq ASC",
                (row["job_id"],),
            ).fetchall()
            events = [
                JobEvent(
                    seq=int(r["seq"]),
                    ts=float(r["ts"]),
                    level=str(r["level"]),
                    message=str(r["message"]),
                    step=str(r["step"] or ""),
                )
                for r in ev_rows
            ]
        return JobRecord(
            job_id=str(row["job_id"]),
            job_type=str(row["job_type"]),
            status=str(row["status"]),
            payload=payload if isinstance(payload, dict) else {},
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            started_at=float(row["started_at"]) if row["started_at"] is not None else None,
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            progress_step=str(row["progress_step"] or ""),
            error=str(row["error_text"]) if row["error_text"] is not None else None,
            result=result if isinstance(result, dict) else None,
            events=events,
        )

    @staticmethod
    def _json_or_default(value: Any, default: Any) -> Any:
        if value in (None, ""):
            return default
        try:
            return json.loads(value)
        except Exception:
            return default


class CorrelationJobWorker:
    def __init__(
        self,
        orchestrator: JobOrchestrator,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
        poll_timeout_seconds: float = 0.5,
    ) -> None:
        self._orchestrator = orchestrator
        self._handler = handler
        self._poll_timeout_seconds = poll_timeout_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="correlation-job-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout_seconds: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout_seconds)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            job_id = self._orchestrator.next_job_id(timeout=self._poll_timeout_seconds)
            if not job_id:
                continue
            job = self._orchestrator.get(job_id)
            if not job:
                continue
            if job.status != "queued":
                continue
            self._orchestrator.mark_running(job_id, step="correlation")
            self._orchestrator.progress(job_id, "Correlation processing started", step="correlation")
            try:
                result = self._handler(job.payload)
            except Exception as exc:  # pragma: no cover
                self._orchestrator.fail(job_id, str(exc))
                continue
            self._orchestrator.complete(job_id, result)
