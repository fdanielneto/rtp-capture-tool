from __future__ import annotations

import logging
from pathlib import Path

from rtphelper.services.decryption_service import DecryptionService
from rtphelper.services.sip_parser import parse_sip_pcap
from rtphelper.services.stream_matcher import StreamMatch

LOGGER = logging.getLogger(__name__)


def decrypt_workflow(sip_pcap: Path, media_pcap: Path, call_id: str | None, out_dir: Path) -> Path:
    LOGGER.info(
        "Decrypt workflow start sip_pcap=%s media_pcap=%s call_id_filter=%s out_dir=%s",
        sip_pcap,
        media_pcap,
        call_id or "-",
        out_dir,
        extra={"category": "SRTP_DECRYPT"},
    )
    parsed = parse_sip_pcap(sip_pcap)
    call = None

    if call_id:
        call = parsed.calls.get(call_id)
    if call is None and parsed.calls:
        call = list(parsed.calls.values())[0]
    if call is None:
        raise ValueError("No SIP call information found")

    stream = StreamMatch(
        host_id="single",
        source_pcaps=[media_pcap],
        src_ip="0.0.0.0",
        src_port=0,
        dst_ip="0.0.0.0",
        dst_port=0,
        ssrc=0,
        packet_count=0,
    )

    service = DecryptionService()
    results = service.decrypt_streams("auto", call, [stream], out_dir)
    success = next((item for item in results if item.output_file), None)
    if not success:
        messages = "; ".join(item.message for item in results)
        LOGGER.error("Decrypt workflow failed reason=%s", messages, extra={"category": "ERRORS", "correlation_id": call.call_id or "-"})
        raise ValueError(f"Decryption failed: {messages}")
    LOGGER.info("Decrypt workflow completed output=%s", success.output_file, extra={"category": "SRTP_DECRYPT", "correlation_id": call.call_id or "-"})
    return success.output_file
