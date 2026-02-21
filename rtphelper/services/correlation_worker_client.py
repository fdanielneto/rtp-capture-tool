from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict


def run_correlation_job_via_subprocess(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute one correlation job in an isolated subprocess.
    Keeps the long-lived worker process independent from rtphelper.web.app imports.
    """
    upload_path = Path(str(payload.get("upload_path", "")).strip())
    if not upload_path.exists() or not upload_path.is_file():
        raise ValueError(f"Uploaded SIP pcap not found for job: {upload_path}")

    python_bin = os.environ.get("RTPHELPER_WORKER_PYTHON", sys.executable).strip() or sys.executable
    timeout_s = int(os.environ.get("RTPHELPER_CORRELATION_JOB_TIMEOUT_SECONDS", "3600") or "3600")
    proc = subprocess.run(
        [python_bin, "-m", "rtphelper.services.correlation_worker_subprocess"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=max(60, timeout_s),
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        details = stderr or stdout or f"subprocess exit={proc.returncode}"
        raise RuntimeError(f"Correlation subprocess failed: {details}")
    try:
        return json.loads(proc.stdout or "{}")
    except Exception as exc:
        raise RuntimeError(f"Invalid correlation subprocess output: {proc.stdout!r}") from exc

