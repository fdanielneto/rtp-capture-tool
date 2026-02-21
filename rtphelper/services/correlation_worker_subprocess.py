from __future__ import annotations

import json
import sys
from typing import Any, Dict


def main() -> int:
    raw = sys.stdin.read()
    payload: Dict[str, Any] = json.loads(raw) if raw.strip() else {}
    # Lazy import in isolated process.
    from rtphelper.web.app import _run_correlation_job_payload

    result = _run_correlation_job_payload(payload)
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

