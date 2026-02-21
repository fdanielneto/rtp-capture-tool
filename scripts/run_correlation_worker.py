#!/usr/bin/env python3
from __future__ import annotations

import os
import signal
import time
from pathlib import Path

from rtphelper.env_loader import load_env_file
from rtphelper.logging_setup import setup_logging
from rtphelper.services.correlation_worker_client import run_correlation_job_via_subprocess
from rtphelper.services.job_orchestrator import CorrelationJobWorker, JobOrchestrator


def main() -> None:
    setup_logging()
    base_dir = Path(__file__).resolve().parents[1]
    env_path = Path(os.environ.get("RTPHELPER_ENV_FILE", base_dir / "config" / "runtime.env"))
    load_env_file(env_path)
    job_db_path = Path(os.environ.get("RTPHELPER_JOB_DB_PATH", str(base_dir / "logs" / "jobs.sqlite3"))).expanduser()
    orchestrator = JobOrchestrator(
        db_path=job_db_path,
        max_queue_size=int(os.environ.get("RTPHELPER_JOB_QUEUE_SIZE", "256")),
    )
    worker = CorrelationJobWorker(orchestrator, run_correlation_job_via_subprocess)
    worker.start()
    running = True

    def _stop(_sig, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while running:
        time.sleep(0.5)

    worker.stop()


if __name__ == "__main__":
    main()
