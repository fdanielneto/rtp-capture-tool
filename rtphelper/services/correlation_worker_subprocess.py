from __future__ import annotations

import json
import sys
from typing import Any, Dict

from rtphelper.services.correlation_progress import progress_emitter_context

PROGRESS_PREFIX = "__RTPHELPER_PROGRESS__ "


def main() -> int:
    raw = sys.stdin.read()
    payload: Dict[str, Any] = json.loads(raw) if raw.strip() else {}
    # Lazy import in isolated process.
    from rtphelper.web.app import _run_correlation_job_payload

    def _emit_progress(event: Dict[str, str]) -> None:
        sys.stderr.write(f"{PROGRESS_PREFIX}{json.dumps(event, ensure_ascii=True)}\n")
        sys.stderr.flush()

    with progress_emitter_context(_emit_progress):
        result = _run_correlation_job_payload(payload)
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
