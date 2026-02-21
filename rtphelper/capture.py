from __future__ import annotations

import datetime as dt
import time
import logging
from pathlib import Path

from rtphelper.logging_setup import correlation_context, short_uuid
from rtphelper.utils import ensure_dir, run_subprocess

DEFAULT_RPCAP_PORT = 2002
LOGGER = logging.getLogger(__name__)


def build_rpcap_interface(host: str, iface: str, port: int = DEFAULT_RPCAP_PORT) -> str:
    return f"rpcap://{host}:{port}/{iface}"


def start_capture(
    media_host: str,
    iface: str,
    bpf_filter: str,
    duration: int | None,
    out_dir: Path,
) -> Path:
    cid = short_uuid()
    start_ts = time.perf_counter()
    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"media_{ts}.pcap"
    ensure_dir(out_file)
    rpcap_if = build_rpcap_interface(media_host, iface)

    cmd = ["dumpcap", "-F", "pcap", "-i", rpcap_if, "-w", str(out_file)]
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    if duration:
        cmd += ["-a", f"duration:{duration}"]

    with correlation_context(cid):
        LOGGER.info("Starting capture command host=%s iface=%s output=%s", media_host, iface, out_file, extra={"category": "CAPTURE"})
        LOGGER.debug("Capture command args=%s", cmd, extra={"category": "CAPTURE"})
        proc = run_subprocess(cmd, check=False)
        elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
        LOGGER.info(
            "Capture process completed host=%s iface=%s exit_code=%s duration_ms=%s output=%s",
            media_host,
            iface,
            proc.returncode,
            elapsed_ms,
            out_file,
            extra={"category": "CAPTURE"},
        )
        if proc.stdout:
            LOGGER.debug("dumpcap stdout (truncated 500 chars): %s", proc.stdout[:500], extra={"category": "CAPTURE"})
        if proc.stderr:
            LOGGER.debug("dumpcap stderr (truncated 500 chars): %s", proc.stderr[:500], extra={"category": "CAPTURE"})
    if proc.returncode != 0:
        LOGGER.error("Capture failed host=%s iface=%s stderr=%s", media_host, iface, proc.stderr[:500], extra={"category": "ERRORS"})
        raise RuntimeError(f"Capture failed: {proc.stderr}")

    return out_file
