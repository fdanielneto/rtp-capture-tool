.PHONY: install run-app run-worker start test e2e-tests e2e e2e_tests e2e-test bench-throughput load-test

install:
	python -m pip install -e '.[dev]'

run-app:
	RTPHELPER_EMBEDDED_WORKER=0 ./scripts/run.sh

run-worker:
	@bash -c 'set -euo pipefail; \
	if [[ -x ".venv/bin/python" ]]; then PY=".venv/bin/python"; else PY="python3"; fi; \
	$$PY scripts/run_correlation_worker.py'

start:
	@bash -c 'set -euo pipefail; \
	if lsof -iTCP:8000 -sTCP:LISTEN -nP >/dev/null 2>&1; then \
	  echo "Port 8000 is already in use. Stop existing app first."; \
	  exit 1; \
	fi; \
	if [[ -x ".venv/bin/python" ]]; then PY=".venv/bin/python"; else PY="python3"; fi; \
	RTPHELPER_EMBEDDED_WORKER=0 ./scripts/run.sh & app_pid=$$!; \
	trap "kill $$app_pid 2>/dev/null || true" EXIT INT TERM; \
	$$PY scripts/run_correlation_worker.py'

test:
	@bash -c 'set -euo pipefail; \
	if [[ -x ".venv/bin/python" ]]; then PY=".venv/bin/python"; else PY="python3"; fi; \
	$$PY -m pytest -q'

e2e-tests:
	@bash -c 'set -euo pipefail; \
	if [[ -x ".venv/bin/python" ]]; then PY=".venv/bin/python"; else PY="python3"; fi; \
	$$PY scripts/e2e_correlation_replay.py'

e2e: e2e-tests

e2e_tests: e2e-tests

e2e-test: e2e-tests

bench-throughput:
	.venv/bin/python scripts/throughput_benchmark.py

load-test:
	.venv/bin/python scripts/load_test_capture_s3.py --start-pps 30000 --upload-modes 3,1,5,0 --local-write-limit-mbps 1000 --pending-upload-threshold-mb 5120
