# RTP Capture Tool

**Production-grade web application for VoIP support teams to remotely capture RTP/SRTP media from rpcapd hosts, correlate SIP signaling with media streams, and generate troubleshooting PCAP files.**

---

## Quick Start

### Prerequisites

**Supported Platforms:**
- macOS (Apple Silicon M1 or newer, arm64)
- The app validates platform compatibility at startup

**System Requirements:**
```bash
brew update
brew install python@3.14 wireshark
```

**Notes:**
- Python `>=3.10` required (`3.14` recommended)
- `dumpcap` must be available in `PATH`
- `tshark` strongly recommended for correlation features

---

## Installation

### 1. Clone Repository

```bash
git clone <your-repo-url>
cd rtp-capture-tool
```

### 2. Create Virtual Environment

```bash
python3.14 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
make install
```

**Alternative:**
```bash
python -m pip install -e '.[dev]'
```

---

## Configuration

### Create Config Files

```bash
cp config/hosts.yaml.example config/hosts.yaml
cp config/runtime.env.example config/runtime.env
```

### Edit `config/hosts.yaml`

Define your environments, regions, and media hosts:

```yaml
rpcap:
  default_port: 2002
  auth_mode: null

settings:
  default_capture_root: ~/Downloads

environments:
  PRD:
    regions:
      US:
        sub-region:
          us-west-2:
            hosts:
              - id: prd-usw2-rtp-1
                address: 1.1.1.1
                description: Production US West media node 1
                interfaces: ["eth0"]
```

**Key Configuration Rules:**
- Each host must define at least one network interface
- UI region/host selectors populate from this file
- `default_capture_root` sets session directory (overridable via `RTPHELPER_CAPTURE_ROOT`)

### Configure Runtime Environment (Optional)

Edit `config/runtime.env` for S3 storage, performance tuning, etc.

**Important Variables:**
```bash
RTPHELPER_STORAGE_MODE=s3        # or 'local'
RTPHELPER_S3_ENDPOINT=https://s3.amazonaws.com
RTPHELPER_S3_REGION=us-west-2
RTPHELPER_S3_PATH=my-bucket/captures
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

---

## Running the Application

### Option 1: Single Command (Recommended)

```bash
make start
```

This starts:
- **Web/API server** on `127.0.0.1:8000`
- **Correlation worker** process

Open browser: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### Option 2: Two-Terminal Mode

**Terminal 1 (Web/API):**
```bash
make run-app
```

**Terminal 2 (Worker):**
```bash
make run-worker
```

---

## Usage Workflow

### Start Media Capture

1. Click **"Start Media Capture"**
2. Select storage destination (**Local** or **AWS S3**)
3. Choose **Environment → Region → Sub-Region → Hosts**
4. Set capture filter (leave empty for `udp`) and timeout
5. Click **"Start Capture"**
6. Monitor live packet counters
7. Click **"Stop Capture"** when ready

### Correlate SIP with Media

1. Upload **SIP PCAP** file
2. Select call direction:
   - **Inbound**: Carrier → RTP Engine → Core
   - **Outbound**: Core → RTP Engine → Carrier
3. Click **"Run Correlation"**
4. Wait for processing (auto-detect + filter + decrypt)
5. Download final outputs:
   - `media_raw.pcap` (filtered RTP streams)
   - `media_decrypted.pcap` (decrypted SRTP)
   - `SIP_plus_media_decrypted.pcap` (merged SIP + media)

### Import Existing Captures

1. Click **"Process Call"**
2. Choose **Local Directory** or **S3**
3. Upload SIP PCAP and select direction
4. Run correlation on imported media files

---

## Output Structure

Session directory:
```
<capture_root>/<optional_folder>/<session_timestamp>/
├── raw/                    # Raw rolling captures per host
├── uploads/                # Uploaded SIP PCAPs
├── decrypted/              # Per-file decrypted outputs
└── combined/
    ├── filtered/           # Per-leg filtered PCAPs
    ├── media_raw.pcap
    ├── media_decrypted.pcap
    └── SIP_plus_media_decrypted.pcap
```

**Default `capture_root`:** `~/Downloads` (configurable)

---

## Testing

### Run Unit Tests

```bash
make test
```

### Run E2E Tests (Local Replay)

```bash
make e2e-tests
```

**Note:** E2E artifacts can be large; stored in `e2e-tests/` directory.

---

## Documentation

### Guides

- **[SIP/Media Correlation Guide](docs/CORRELATION_GUIDE.md)** - Deep dive into component detection, filter construction, and manual CLI correlation
- **[DNS Resolution Strategy](docs/DNS_RESOLUTION.md)** - Host mapping and DNS caching behavior

### Architecture Overview

- **Web:** FastAPI + Jinja2 templates + vanilla JavaScript
- **Capture:** Direct RPCAP client with multi-host parallel capture and rolling PCAP writer
- **Parser:** SIP/SDP parsing via `scapy`
- **Correlation:** `tshark`-based per-leg/per-file filtering with RTP Engine detection
- **Decryption:** `pylibsrtp` with SDES inline key selection
- **Logging:** Structured logs with correlation IDs

### Repository Structure

```
rtphelper/
├── web/                   # Web routes, templates, static assets
├── services/
│   ├── capture_service.py    # Capture orchestration
│   ├── sip_parser.py          # SIP/SDP parsing
│   ├── sip_correlation.py     # Media correlation engine
│   ├── decryption_service.py  # SRTP decryption
│   └── ...
├── rpcap/                 # RPCAP client, BPF compiler, PCAP writer
├── config_loader.py       # Host config schema/validation
└── ...

config/
├── hosts.yaml             # Environment/region/host definitions
└── runtime.env            # Runtime configuration

docs/
├── CORRELATION_GUIDE.md   # Complete correlation technical reference
└── DNS_RESOLUTION.md      # DNS resolution strategy

scripts/
├── rpcap_diagnose.py      # Connectivity diagnostic tool
└── ...

logs/
└── app.log                # Rotating application log (10 MB × 10 backups)

tests/
└── ...                    # Unit tests
```

---

## Troubleshooting

### Installation Issues

**Problem:** `pylibsrtp` fails to compile/link on macOS Apple Silicon

**Solution:**
```bash
export LDFLAGS="-L/opt/homebrew/lib"
export CPPFLAGS="-I/opt/homebrew/include"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
make install
```

---

### Capture Issues

**Problem:** Cannot start capture

**Solution:** Run diagnostic tool:
```bash
.venv/bin/python scripts/rpcap_diagnose.py --config config/hosts.yaml
```

**Common causes:**
- RPCAP host unreachable
- Firewall blocking port 2002
- Interface name mismatch
- Insufficient permissions on remote host

---

### Correlation Issues

**Problem:** Correlation generated no downloads

**Check:**
1. Verify SIP PCAP overlaps media capture time window
2. Confirm correct call direction selected (Inbound vs Outbound)
3. Review logs in UI or `logs/app.log`
4. Ensure SIP call is complete (INVITE + 200 OK/183)

**Problem:** Only `-no-decrypt-need` files generated (no decryption)

**Check:**
1. Verify SIP contains `a=crypto:` lines in INVITE/200 OK
2. Confirm crypto suite is supported (AES_CM_128, AES_256_GCM)
3. Check that RTP is actually encrypted (RTP/SAVP, not RTP/AVP)

**Problem:** `core_to_rtpengine` leg finds no packets (Inbound)

**Known Limitation:** In inbound calls, Core's original 200 OK is modified by RTP Engine. Original Core media endpoint may not be visible.

**Workaround:** Rely on other legs or manually construct filter if Core IP is known.

---

### Logging

**Log Location:** `logs/app.log`

**Log Rotation:** 10 MB per file, 10 backups

**Set Log Level:**
```bash
export RTPHELPER_LOG_LEVEL=DEBUG
make start
```

**Health Check:**
```bash
curl http://127.0.0.1:8000/api/health
```

---

## Security Considerations

**⚠️ WARNING:** RPCAP commonly runs with **null authentication** on port `2002`. Use only in trusted internal networks.

**Recommendations:**
- Restrict RPCAP access via firewall/ACL
- Never expose RPCAP endpoints publicly
- Keep `config/hosts.yaml` access-controlled
- Review `runtime.env` for sensitive credentials (AWS keys, etc.)

---

## Known Limitations

- SIP parsing and transaction pairing are best-effort for complex topologies
- Decryption depends on valid keying material in SIP signaling
- Some environments require `tshark`/`dumpcap` permission tuning
- Multi-leg calls with >2 Call-IDs may require manual correlation

---

## CLI (Legacy)

Legacy CLI commands remain available:

```bash
rtphelper capture
rtphelper decrypt
rtphelper web
```

**Recommended:** Use web UI for production workflows.

---

## Contributing

Run tests before submitting changes:

```bash
make test
make e2e-tests
```

Follow existing code style and add tests for new features.

---

## License

[Specify license here]

---

## Support

For issues, questions, or feature requests:
- Check `logs/app.log` first
- Review [CORRELATION_GUIDE.md](docs/CORRELATION_GUIDE.md) for correlation troubleshooting
- Run `scripts/rpcap_diagnose.py` for capture connectivity issues

---

**Version:** 1.0  
**Last Updated:** March 5, 2026

