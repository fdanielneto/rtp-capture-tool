from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict

PROGRESS_PREFIX = "__RTPHELPER_PROGRESS__ "


def run_correlation_job_via_subprocess(
    payload: Dict[str, Any],
    on_progress: Callable[[Dict[str, str]], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> Dict[str, Any]:
    """
    Execute one correlation job in an isolated subprocess.
    Keeps the long-lived worker process independent from rtphelper.web.app imports.
    """
    upload_path = Path(str(payload.get("upload_path", "")).strip())
    if not upload_path.exists() or not upload_path.is_file():
        raise ValueError(f"Uploaded SIP pcap not found for job: {upload_path}")

    python_bin = os.environ.get("RTPHELPER_WORKER_PYTHON", sys.executable).strip() or sys.executable
    timeout_s = int(os.environ.get("RTPHELPER_CORRELATION_JOB_TIMEOUT_SECONDS", "3600") or "3600")
    proc = subprocess.Popen(
        [python_bin, "-m", "rtphelper.services.correlation_worker_subprocess"],
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # Keep correlation subprocess and its children in a dedicated process group,
        # so cancellation can terminate tshark/decrypt subprocesses immediately.
        start_new_session=True,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    stdout_chunks: list[str] = []
    stderr_plain: list[str] = []
    stderr_lock = threading.Lock()

    def _read_stdout() -> None:
        while True:
            chunk = proc.stdout.read(8192)
            if not chunk:
                break
            stdout_chunks.append(chunk)

    t_stdout = threading.Thread(target=_read_stdout, name="corr-subproc-stdout", daemon=True)
    t_stdout.start()

    def _read_stderr() -> None:
        while True:
            line = proc.stderr.readline()
            if line == "":
                break
            text = str(line).rstrip("\r\n")
            if text.startswith(PROGRESS_PREFIX):
                raw_event = text[len(PROGRESS_PREFIX) :].strip()
                try:
                    event = json.loads(raw_event)
                    if isinstance(event, dict) and on_progress is not None:
                        on_progress(
                            {
                                "message": str(event.get("message") or ""),
                                "step": str(event.get("step") or "correlation"),
                                "level": str(event.get("level") or "info"),
                            }
                        )
                except Exception:
                    with stderr_lock:
                        stderr_plain.append(text)
            else:
                with stderr_lock:
                    stderr_plain.append(text)

    t_stderr = threading.Thread(target=_read_stderr, name="corr-subproc-stderr", daemon=True)
    t_stderr.start()

    try:
        proc.stdin.write(json.dumps(payload))
        proc.stdin.close()
    except Exception:
        pass

    deadline = time.time() + max(60, timeout_s)
    returncode: int | None = None
    try:
        while True:
            if should_cancel is not None and should_cancel():
                _terminate_subprocess_group(proc, force_after_seconds=1.5)
                raise RuntimeError("Correlation canceled by user")
            returncode = proc.poll()
            if returncode is not None:
                break
            if time.time() >= deadline:
                _terminate_subprocess_group(proc, force_after_seconds=1.0)
                raise RuntimeError(f"Correlation subprocess timed out after {max(60, timeout_s)}s")
            time.sleep(0.2)
    finally:
        t_stdout.join(timeout=1.0)
        t_stderr.join(timeout=1.0)

    stdout_text = "".join(stdout_chunks)
    with stderr_lock:
        stderr_text = "\n".join([s for s in stderr_plain if s.strip()]).strip()

    if returncode != 0:
        stdout = (stdout_text or "").strip()
        stderr = (stderr_text or "").strip()
        details = stderr or stdout or f"subprocess exit={proc.returncode}"
        raise RuntimeError(f"Correlation subprocess failed: {details}")
    try:
        return json.loads(stdout_text or "{}")
    except Exception as exc:
        raise RuntimeError(f"Invalid correlation subprocess output: {stdout_text!r}") from exc


def _terminate_subprocess_group(proc: subprocess.Popen[str], force_after_seconds: float = 1.5) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            return
    deadline = time.time() + max(0.1, float(force_after_seconds))
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
