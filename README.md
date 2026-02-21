# rtp-capture-tool

Production-oriented web application for first-line VoIP support teams to capture RTP/SRTP remotely from `rpcapd` hosts, correlate SIP with media, and generate troubleshooting PCAP outputs.

## Overview

This project provides a browser workflow to:
- Start/stop remote packet capture on multiple media hosts (via `rpcapd`).
- Apply a capture BPF filter (defaults to `udp` when empty).
- Store raw capture files per host with rolling PCAP chunks (default 500 MB; configurable).
- Import existing media capture files from local directories.
- Upload a SIP PCAP and select call direction (`Inbound` or `Outbound`).
- Auto-detect carrier/core signaling/media context from SIP and run media correlation.
- Build final outputs:
  - `media_raw.pcap`
  - `media_decrypted.pcap`
  - `SIP_plus_media_decrypted.pcap`

Primary use case: VoIP incident troubleshooting in trusted internal environments.

## Primary Platform Support

Primary supported and tested target:
- macOS 14+ on Apple Silicon (`arm64`, M1 or newer)

Other platforms are outside the primary support scope and are not officially supported.

## Current Architecture

- Web app: `FastAPI` + Jinja templates + vanilla JS.
- Capture engine: direct RPCAP client (`rtphelper/rpcap/*`) with multi-host parallel capture and rolling PCAP writer.
- SIP parser: parses SIP/SDP from uploaded PCAP (`scapy`).
- Correlation pipeline: `tshark`-based per-leg/per-file filtering.
- Decryption engine: `pylibsrtp` with SDES inline selection by INVITE/200 OK suite intersection.
- Logging: structured, human-readable logs with correlation IDs.

## Repository Structure

- `rtphelper/web/` - web routes, templates, static assets.
- `rtphelper/services/capture_service.py` - capture session orchestration.
- `rtphelper/services/sip_parser.py` - SIP/SDP parsing.
- `rtphelper/services/decryption_service.py` - SRTP decrypt/copy pipeline.
- `rtphelper/rpcap/` - RPCAP protocol client, BPF compile, frame normalization, PCAP rolling writer.
- `rtphelper/config_loader.py` - hosts config schema and validation.
- `config/hosts.yaml` - multi-region host definitions.
- `config/hosts.yaml.example` - safe template for host/environment definitions.
- `config/runtime.env` - local runtime environment variables loaded by the app.
- `config/runtime.env.example` - safe template for runtime environment variables.
- `scripts/rpcap_diagnose.py` - local compatibility/connectivity diagnostic script.
- `logs/app.log` - rotating application log.
- `tests/` - unit tests.

## Prerequisites (macOS ARM)

Install dependencies:

```bash
brew update
brew install python@3.14 wireshark
```

Notes:
- `dumpcap` and `tshark` are required (provided by Wireshark tools).
- Python requirement is `>=3.10` (recommended: `3.14`).
- If `pylibsrtp` build/link fails:

```bash
export LDFLAGS="-L/opt/homebrew/lib"
export CPPFLAGS="-I/opt/homebrew/include"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
```

## Installation

1. Check your current default Python:

```bash
python3 --version
```

2. If `python3` is lower than `3.10`, set Python 3.14 as default in your shell:

```bash
brew install python@3.14
echo 'export PATH="/opt/homebrew/opt/python@3.14/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
python3 --version
```

3. Create and activate the virtual environment using the default `python3`:

```bash
git clone <your-repo-url>
cd rtp-capture-tool
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Alternative (without changing shell default):

```bash
git clone <your-repo-url>
cd rtp-capture-tool
python3.14 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

No database migrations are required.

## Configuration

Create your local config from templates:

```bash
cp config/hosts.yaml.example config/hosts.yaml
cp config/runtime.env.example config/runtime.env
```

Edit `config/hosts.yaml`:

```yaml
rpcap:
  default_port: 2002
  auth_mode: null
settings:
  default_capture_root: /absolute/path/for/captures
environments:
  PRD:
    regions:
      EU:
        sub-region:
          eu-west-1:
            hosts:
              - id: <host_id>
                address: <host_IP>
                description: <host_description>
                interfaces: ["<host_interface_name>"]
      US:
        sub-region:
          us-east-1:
            hosts:
              - id: prd-rtp_host-1
                address: 1.1.1.1
                description: PRD US East 1 media node 1
                interfaces: ["pkt0"]
  QA:
    regions:
      EU:
        sub-region:
          eu-west-1:
            hosts:
              - id: qa-rtp_host-1
                address: 2.2.2.2
                description: QA EU West 1 media node 1
                interfaces: ["ens5"]
  STG:
    regions: {}
```

Rules:
- Each host needs at least one interface.
- Region/host selectors in UI are populated from this file.
- `settings.default_capture_root` sets the default destination root for capture/import sessions.
- Env var `RTPHELPER_CAPTURE_ROOT` overrides `settings.default_capture_root` when present.

Runtime env file:
- The app auto-loads `config/runtime.env` at startup (if present).
- You can point to another file with `RTPHELPER_ENV_FILE=/path/to/file.env`.

### S3 Storage (Default) with Automatic Local Fallback

By default, the app tries to persist capture artifacts in Amazon S3. If S3 becomes unavailable, it automatically falls back to local storage.

Environment variables:

- `RTPHELPER_STORAGE_MODE`:
  - `s3` (default) -> try S3 first, fallback to local on failure
  - `local` -> always local
- `RTPHELPER_S3_ENDPOINT` (default: `s3.amazonaws.com`)
- `RTPHELPER_S3_REGION` (default: `eu-west-1`)
- `RTPHELPER_S3_PATH` (recommended: set explicitly)
  - format: `<bucket>/<optional/prefix>`
- `RTPHELPER_S3_BUCKET` (optional override of bucket from `RTPHELPER_S3_PATH`)
- `RTPHELPER_S3_PREFIX` (optional override of prefix from `RTPHELPER_S3_PATH`)
- `RTPHELPER_S3_POOL_CAPTURE` (optional, default: `6`)
  - S3 HTTP connection pool while capture is active.
- `RTPHELPER_S3_POOL_POST_CAPTURE` (optional, default: `60`)
  - S3 HTTP connection pool after capture stops (final flush/upload phase).
- `RTPHELPER_S3_UPLOAD_WORKERS_MAX` (optional, default: `6`)
  - Number of background upload workers consuming the persistent S3 upload queue.
- `RTPHELPER_S3_UPLOAD_CONCURRENCY_CAPTURE` (optional, default: `2`)
  - Max concurrent uploads while capture is active.
- `RTPHELPER_S3_UPLOAD_CONCURRENCY_POST_CAPTURE` (optional, default: `4`)
  - Max concurrent uploads after capture stops (final flush phase).
- `RTPHELPER_S3_UPLOAD_MAX_ATTEMPTS` (optional, default: `5`)
  - Max retries per upload file before marking it as failed.
- `RTPHELPER_S3_MAX_POOL_CONNECTIONS` (optional, default: `10`)
  - Base botocore pool size if phase tuning is not applied.
- `RTPHELPER_S3_MAINTENANCE_MAX_FILES_ACTIVE` (optional, default: `50`)
  - Max files inspected per maintenance cycle while capture is active.
- `RTPHELPER_S3_MULTIPART_THRESHOLD_BYTES` (optional, default: `200MB`)
- `RTPHELPER_S3_MULTIPART_CHUNKSIZE_BYTES` (optional, default: `100MB`)
- `RTPHELPER_S3_MULTIPART_MAX_CONCURRENCY` (optional, default: `10`)
- `RTPHELPER_S3_MULTIPART_USE_THREADS` (optional, default: `1`)
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (optional)
- `RTPHELPER_ROLLING_PCAP_MAX_BYTES` (optional, default: `500MB`)
  - Controls raw capture file rollover size per host.
  - Example: `RTPHELPER_ROLLING_PCAP_MAX_BYTES=1GB` for 1 GB chunks.
- `RTPHELPER_ROLLING_PCAP_MAX_SECONDS` (optional, default: `0`)
  - Time-based rollover safeguard for low-traffic captures.
- `RTPHELPER_LOCAL_SPOOL_MAX_BYTES` (optional, default: `5368709120` = 5 GB)
  - Local spool cap when S3 mode is active.
- `RTPHELPER_RPCAP_RECONNECT_BASE_SECONDS` (optional, default: `2`)
- `RTPHELPER_RPCAP_RECONNECT_MAX_SECONDS` (optional, default: `30`)
- `RTPHELPER_RPCAP_RECONNECT_MAX_ATTEMPTS` (optional, default: `3`)
  - Per-host reconnect policy when a RPCAP stream drops during capture.

Recommended setup:
- Edit `config/runtime.env` with your environment-specific values.

Notes:
- S3 object keys keep the same relative session layout:
  - `<environment>/<optional_output_folder>/<session_timestamp>/raw/...`
  - `<environment>/<optional_output_folder>/<session_timestamp>/uploads/...`
  - `<environment>/<optional_output_folder>/<session_timestamp>/decrypted/...`
  - `<environment>/<optional_output_folder>/<session_timestamp>/combined/...`

## Run

Single command (recommended in development):

```bash
make start
```

Two-terminal mode:

Terminal 1 (web/API):

```bash
./scripts/run.sh
```

Terminal 2 (worker):

```bash
make run-worker
```

Open: [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Single-node Production Mode (macOS M1)

This project supports a simplified control/data split on one Mac:

- Control plane: web/API (`make run-app`)
- Data plane: correlation worker (`make run-worker`)
- Durable job queue/state: SQLite (`logs/jobs.sqlite3` by default)

Recommended commands:

Terminal 1 (web/API without embedded worker):

```bash
export RTPHELPER_EMBEDDED_WORKER=0
make run-app
```

Terminal 2 (dedicated worker):

```bash
make run-worker
```

Relevant env vars:

- `RTPHELPER_JOB_DB_PATH` (default: `logs/jobs.sqlite3`)
- `RTPHELPER_JOB_QUEUE_SIZE` (default: `256`)
- `RTPHELPER_WORKER_PYTHON` (optional, default: current `python`)
  - Python binary used by the external worker to spawn isolated correlation subprocesses.
- `RTPHELPER_CORRELATION_JOB_TIMEOUT_SECONDS` (optional, default: `3600`)
  - Hard timeout per correlation subprocess job.
- `RTPHELPER_EMBEDDED_WORKER`:
  - `1` (default): worker runs inside web process
  - `0`: run worker as separate process (`make run-worker`)

## Web Workflow (Current)

1. Click `Start Media Capture` or `Process Call` from the home panel.
2. For `Start Media Capture`, choose `Capture files location`:
   - `Local`
   - `AWS S3` (shows an optional local temporary spool directory picker)
3. Select environment, region/sub-regions, and hosts.
4. Optionally set capture filter (empty => `udp`) and timeout (minutes).
5. Start capture and monitor live host packet counters.
6. Stop capture.
7. In Post-capture:
   - Upload SIP PCAP.
   - Select call direction (`Inbound` or `Outbound`).
   - If S3 flush is pending, wait for completion (or resume flush) before correlation.
   - Click `Run Correlation`.
8. Download final files when processing ends.

Alternative:
- Click `Process Call` to import media files:
  - from a local directory (`Choose local directory`), or
  - from S3 (`Use S3 session` -> `Import from S3`)
  and continue directly to correlation.

## Correlation & Processing Logic (Current)

After SIP upload and direction selection:

1. Parse the SIP call and resolve:
   - First INVITE source/destination.
   - Last negotiation host IP.
   - Carrier/core role based on direction.
2. Resolve media request/reply RTP ports from SDP `m=audio` for:
   - carrier-host pair.
   - host-core pair.
3. Build leg filters and run `tshark` per leg against each raw media PCAP.
4. For each leg/file:
   - count packets (`tshark ... | wc -l`).
   - if count `> 10`, create `*-filtered.pcap`.
5. Merge all filtered files into `media_raw.pcap`.
6. Process each filtered file:
   - decrypt when possible (`*-decrypted.pcap`),
   - otherwise copy as `*-no-decrypt-need.pcap`.
7. Merge processed media into `media_decrypted.pcap`.
8. Merge SIP upload and `media_decrypted.pcap` into `SIP_plus_media_decrypted.pcap`.

## Output Layout

Session directory:

`<capture_root>/<optional_user_folder>/<session_timestamp>/`

Default `capture_root`:
- `~/Downloads` (if not overridden)

Common subfolders:
- `raw/` - raw rolling captures: `<region>-<host>-0001.pcap`, ...
- `uploads/` - uploaded SIP PCAPs.
- `decrypted/` - per-file `-decrypted` / `-no-decrypt-need` outputs.
- `combined/`
  - `filtered/` (`*-filtered.pcap`)
  - `media_raw.pcap`
  - `media_decrypted.pcap`
  - `SIP_plus_media_decrypted.pcap`

## Logging

- Console + rotating file log.
- Log file: `logs/app.log`
- Rotation: 10 MB per file, 10 backups.
- Format:

```text
%(asctime)s | %(levelname)s | %(category)s | cid=%(correlation_id)s | %(name)s | %(filename)s:%(lineno)d %(funcName)s() | %(message)s
```

- Set level:

```bash
export RTPHELPER_LOG_LEVEL=DEBUG
```

- `DEBUG` includes request/response tracing, filter construction, per-file `tshark` activity, and decryption details.
- `correlation_id` uses SIP `Call-ID` when available; otherwise short UUID.
- Health endpoint:
  - `GET /api/health`

## Tests

```bash
make test
```

Current unit coverage includes:
- config loading/validation
- SIP parsing basics
- stream matching helpers

### E2E Replay Tests (Local Cases)

End-to-end replay tests are available via:

```bash
make e2e-tests
```

Important:
- The `e2e-tests/` folder is intentionally **not** committed to the repository (large PCAP artifacts).
- Each team/user should create local E2E cases on their own machine.
- The replay script reads source artifacts from `e2e-tests/` and copies them to a temporary sandbox (`/tmp`) before execution, so it does not depend on `captures/` for writes.

Expected local layout:

```text
e2e-tests/
  inbound/
    20260217_021435/
      raw/
      uploads/
      rtp-capture-tool-logs-*.txt
  outbound/
    20260217_020948/
      raw/
      uploads/
      rtp-capture-tool-logs-*.txt
```

How to create a case:
1. Start from a successful real session folder (timestamp folder with `raw/`, `uploads/`, and exported `rtp-capture-tool-logs-*.txt`).
2. Copy that timestamp folder into a case directory under `e2e-tests/<case-name>/`.
3. Repeat for additional scenarios. New directories under `e2e-tests/` are automatically picked up as new test cases.

Notes:
- If a case directory contains multiple timestamp folders, the script uses the latest one by folder name.
- Direction (`inbound`/`outbound`) is inferred from each case log line (`INFO: Direction:`), so no manual direction config is required.
- The script continues running remaining cases even if one case fails and prints a final summary.

## Security Considerations

`rpcapd` is used with null authentication on default port `2002`.
Use this only in trusted internal networks.

Recommendations:
- Restrict network access to RPCAP hosts via firewall/ACL.
- Do not expose RPCAP endpoints publicly.
- Keep host list in `config/hosts.yaml` tightly controlled.

## Limitations (Current)

- SIP parsing and transaction pairing are best-effort for complex SIP topologies.
- Decryption depends on valid SDES/DTLS keying material present in signaling context.
- RTP filter thresholds are fixed in code (`count > 10` to keep filtered file).
- Some deployments may require tuning `tshark`/`dumpcap` permissions and PATH setup.

## Troubleshooting

### Cannot start capture
- Run:

```bash
.venv/bin/python scripts/rpcap_diagnose.py --config config/hosts.yaml
```

- Validate host/interface reachability and local capture tool availability.

### Correlation produced no downloads
- Check app logs (`logs/app.log`) and UI log section in `Debug`.
- Confirm SIP PCAP contains the same call window as media captures.
- Confirm call direction selection is correct (`Inbound`/`Outbound`).

### Decryption produced only `-no-decrypt-need` outputs
- Check SDP/crypto negotiation in SIP PCAP.
- Validate that inline/keying data exists for the selected call.

## CLI

Legacy CLI commands remain available:

```bash
rtphelper capture
rtphelper decrypt
rtphelper web
```

Recommended operational path is the web UI.
