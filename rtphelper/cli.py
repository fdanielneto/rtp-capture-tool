from __future__ import annotations

import logging
from pathlib import Path

import click
import uvicorn

from rtphelper.capture import start_capture
from rtphelper.decrypt import decrypt_workflow
from rtphelper.logging_setup import setup_logging
from rtphelper.utils import ensure_binaries, ensure_macos_arm

LOGGER = logging.getLogger(__name__)


@click.group()
def main() -> None:
    """rtphelper commands."""
    setup_logging()
    LOGGER.info("CLI bootstrap start", extra={"category": "CONFIG"})
    ensure_macos_arm()
    ensure_binaries()
    LOGGER.info("CLI bootstrap completed", extra={"category": "CONFIG"})


@main.command()
@click.option("--media-host", prompt="Media host (rpcapd)", help="Host/IP running rpcapd.")
@click.option("--iface", prompt="Remote interface (for example: 1, en0)", help="Remote interface id or name.")
@click.option("--filter", "bpf_filter", prompt="Capture BPF filter", help="Example: udp and host 10.11.10.42")
@click.option("--duration", type=int, default=60, show_default=True, help="Capture duration in seconds.")
@click.option("--out-dir", type=click.Path(path_type=Path), default=Path("captures"), show_default=True)
def capture(media_host: str, iface: str, bpf_filter: str, duration: int, out_dir: Path) -> None:
    """Capture media via rpcapd and save encrypted pcap."""
    LOGGER.info(
        "CLI capture command media_host=%s iface=%s filter=%s duration=%s out_dir=%s",
        media_host,
        iface,
        bpf_filter,
        duration,
        out_dir,
        extra={"category": "CAPTURE"},
    )
    start_capture(media_host, iface, bpf_filter, duration, out_dir)


@main.command()
@click.option("--sip-pcap", type=click.Path(exists=True, path_type=Path), prompt="SIP+SDP pcap")
@click.option("--media-pcap", type=click.Path(exists=True, path_type=Path), prompt="Media pcap (SRTP)")
@click.option("--call-id", default=None, help="Optional Call-ID filter")
@click.option("--out-dir", type=click.Path(path_type=Path), default=Path("output"), show_default=True)
def decrypt(sip_pcap: Path, media_pcap: Path, call_id: str | None, out_dir: Path) -> None:
    """Decrypt SDES-SRTP and generate clear RTP pcap."""
    LOGGER.info(
        "CLI decrypt command sip_pcap=%s media_pcap=%s call_id=%s out_dir=%s",
        sip_pcap,
        media_pcap,
        call_id or "-",
        out_dir,
        extra={"category": "SRTP_DECRYPT"},
    )
    decrypt_workflow(sip_pcap, media_pcap, call_id, out_dir)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True, type=int)
def web(host: str, port: int) -> None:
    """Start web application."""
    LOGGER.info("CLI web command host=%s port=%s", host, port, extra={"category": "CONFIG"})
    uvicorn.run("rtphelper.web.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
