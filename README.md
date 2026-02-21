# rtp-capture-tool

Production-oriented web application for first-line VoIP support teams to capture RTP/SRTP remotely from `rpcapd` hosts, correlate SIP with media, and generate troubleshooting PCAP outputs.

## 1) Requirements

This application currently supports only:
- macOS (`Darwin`)
- Apple Silicon (`arm64`, M1 or newer)

The app validates this at startup and exits on unsupported platforms.

Install required system tools:

```bash
brew update
brew install python@3.14 wireshark
```

Notes:
- Python requirement is `>=3.10` (`3.14` is recommended).
- `dumpcap` is required and must be available in `PATH`.
- `tshark` is strongly recommended for correlation and troubleshooting flows.

## 2) Install

Clone the repository and create a virtual environment:

```bash
git clone <your-repo-url>
cd rtp-capture-tool
python3 -m venv .venv
source .venv/bin/activate
```

Install project dependencies (including dev tools):

```bash
make install
```

Alternative equivalent command:

```bash
python -m pip install -e '.[dev]'
```

## 3) Run

Create local configuration files from templates:

```bash
cp config/hosts.yaml.example config/hosts.yaml
cp config/runtime.env.example config/runtime.env
```

Then start the app.

### Recommended (single command)

```bash
make start
```

This starts:
- Web/API process on `127.0.0.1:8000`
- Dedicated correlation worker process

Open in browser: [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Two-terminal mode

Terminal 1 (web/API):

```bash
make run-app
```

Terminal 2 (worker):

```bash
make run-worker
```

## Overview

This project provides a browser workflow to:
- Start/stop remote packet capture on multiple media hosts (via `rpcapd`).
- Apply a capture BPF filter (defaults to `udp` when empty).
- Store raw capture files per host with rolling PCAP chunks (default 500 MB; configurable).
- Import existing media capture files from local directories or S3.
- Upload a SIP PCAP and select call direction (`Inbound` or `Outbound`).
- Auto-detect carrier/core signaling/media context from SIP and run media correlation.
- Build final outputs:
  - `media_raw.pcap`
  - `media_decrypted.pcap`
  - `SIP_plus_media_decrypted.pcap`

Primary use case: VoIP incident troubleshooting in trusted internal environments.

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
- `rtphelper/rpcap/` - RPCAP client, BPF compile, frame normalization, rolling PCAP writer.
- `rtphelper/config_loader.py` - hosts config schema and validation.
- `config/hosts.yaml` - host definitions.
- `config/runtime.env` - runtime environment variables loaded by the app.
- `scripts/rpcap_diagnose.py` - local compatibility/connectivity diagnostic.
- `logs/app.log` - rotating application log.
- `tests/` - unit tests.

## Configuration

### `config/hosts.yaml`

Edit `config/hosts.yaml` with your environment and host map.

Minimal structure example:

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
              - id: prd-rtp-host-1
                address: 1.1.1.1
                description: PRD EU West 1 media node 1
                interfaces: ["pkt0"]
```

Rules:
- Each host must have at least one interface.
- UI region and host selectors are populated from this file.
- `settings.default_capture_root` defines the default session root.
- `RTPHELPER_CAPTURE_ROOT` overrides `settings.default_capture_root` when set.

### `config/runtime.env`

The app auto-loads `config/runtime.env` at startup.
You can point to another env file with `RTPHELPER_ENV_FILE=/path/to/file.env`.

### Storage mode (S3 with local fallback)

Default behavior:
- `RTPHELPER_STORAGE_MODE=s3`
- App tries S3 first and falls back to local storage on failures.

Important variables:
- `RTPHELPER_STORAGE_MODE` (`s3` or `local`)
- `RTPHELPER_S3_ENDPOINT`
- `RTPHELPER_S3_REGION`
- `RTPHELPER_S3_PATH` (`<bucket>/<optional/prefix>`)
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (optional)

Performance and queue tuning variables are available in `config/runtime.env.example`.

## Web Workflow (Current)

1. Click `Start Media Capture` or `Process Call`.
2. For capture, choose destination (`Local` or `AWS S3`).
3. Select environment, region/sub-region, and hosts.
4. Optionally set capture filter (empty => `udp`) and timeout.
5. Start capture and monitor live packet counters.
6. Stop capture.
7. In post-capture:
   - Upload SIP PCAP
   - Select call direction (`Inbound` or `Outbound`)
   - Run correlation
8. Download final files.

Alternative path:
- Use `Process Call` to import media from local directory or from S3, then run correlation directly.

## Correlation & Processing Logic (Current)

After SIP upload and direction selection:

1. Parse SIP call and resolve signaling/media roles.
2. Resolve RTP ports from SDP `m=audio` lines.
3. Build leg filters and combine them with logical `OR`.
4. For each media PCAP:
   - count matching packets
   - create `*-filtered.pcap` when count is above threshold
5. Merge filtered files into `media_raw.pcap`.
6. Process each filtered file:
   - decrypt when possible (`*-decrypted.pcap`)
   - otherwise copy as `*-no-decrypt-need.pcap`
7. Merge processed media into `media_decrypted.pcap`.
8. Merge SIP upload + decrypted media into `SIP_plus_media_decrypted.pcap`.

## Output Layout

Session directory:

`<capture_root>/<optional_user_folder>/<session_timestamp>/`

Default `capture_root`:
- `~/Downloads` (if not overridden)

Common subfolders:
- `raw/` - raw rolling captures (`<region>-<host>-0001.pcap`, ...)
- `uploads/` - uploaded SIP PCAPs
- `decrypted/` - per-file `-decrypted` / `-no-decrypt-need` outputs
- `combined/`
  - `filtered/`
  - `media_raw.pcap`
  - `media_decrypted.pcap`
  - `SIP_plus_media_decrypted.pcap`

## Logging

- Console + rotating file log.
- Log file: `logs/app.log`
- Rotation: 10 MB per file, 10 backups.
- Health endpoint: `GET /api/health`

Set log level:

```bash
export RTPHELPER_LOG_LEVEL=DEBUG
```

## Tests

Run unit tests:

```bash
make test
```

Run local E2E replay tests:

```bash
make e2e-tests
```

Notes:
- `e2e-tests/` artifacts are local and can be large.
- The replay script runs scenarios from local case directories and prints a summary.

## Troubleshooting

### `pylibsrtp` fails to compile/link (macOS Apple Silicon)

Only if installation fails with `pylibsrtp` build/link errors, export:

```bash
export LDFLAGS="-L/opt/homebrew/lib"
export CPPFLAGS="-I/opt/homebrew/include"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
```

Then run installation again:

```bash
make install
```

### Cannot start capture

Run:

```bash
.venv/bin/python scripts/rpcap_diagnose.py --config config/hosts.yaml
```

### Correlation generated no downloads

- Check `logs/app.log` and UI logs.
- Confirm SIP PCAP overlaps the media capture window.
- Confirm call direction selection.

### Decryption generated only `-no-decrypt-need` files

- Check SIP SDP/crypto negotiation.
- Validate that keying material exists for the selected call.

## Security Considerations

`rpcapd` commonly runs with null authentication on port `2002`.
Use only inside trusted internal networks.

Recommendations:
- Restrict RPCAP access via firewall/ACL.
- Never expose RPCAP endpoints publicly.
- Keep `config/hosts.yaml` tightly controlled.

## Limitations (Current)

- SIP parsing and transaction pairing are best-effort for complex SIP topologies.
- Decryption depends on valid keying material in signaling context.
- Some environments require `tshark`/`dumpcap` permission and PATH tuning.

## CLI (Legacy)

Legacy CLI commands remain available:

```bash
rtphelper capture
rtphelper decrypt
rtphelper web
```

Recommended operational path is the web UI.
