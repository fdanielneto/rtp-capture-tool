#!/usr/bin/env bash
set -euo pipefail

export PYTHONUNBUFFERED=1
if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

$PY -m uvicorn rtphelper.web.app:app --host 127.0.0.1 --port 8000
