from __future__ import annotations

import logging
from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter

from rtphelper.services.stream_matcher import StreamMatch

LOGGER = logging.getLogger(__name__)


def extract_stream_to_pcap(stream: StreamMatch, output_pcap: Path) -> tuple[Path, int]:
    """Extract packets matching a StreamMatch across all its source pcaps."""
    output_pcap.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.debug(
        "Extract stream start stream_id=%s output=%s sources=%s",
        stream.stream_id,
        output_pcap,
        [str(p) for p in stream.source_pcaps],
        extra={"category": "FILES"},
    )

    writer = PcapWriter(str(output_pcap), append=False, sync=True)
    count = 0
    try:
        for source in stream.source_pcaps:
            if not source.exists():
                continue
            with PcapReader(str(source)) as reader:
                for pkt in reader:
                    if IP not in pkt or UDP not in pkt or Raw not in pkt[UDP]:
                        continue

                    if pkt[IP].src != stream.src_ip or pkt[IP].dst != stream.dst_ip:
                        continue
                    if int(pkt[UDP].sport) != stream.src_port or int(pkt[UDP].dport) != stream.dst_port:
                        continue

                    payload = bytes(pkt[UDP][Raw].load)
                    if len(payload) < 12 or (payload[0] >> 6) != 2:
                        continue

                    ssrc = int.from_bytes(payload[8:12], byteorder="big")
                    if ssrc != stream.ssrc:
                        continue

                    writer.write(pkt)
                    count += 1
    finally:
        writer.close()

    if count == 0 and output_pcap.exists():
        output_pcap.unlink()
    LOGGER.debug(
        "Extract stream done stream_id=%s packets=%s output_exists=%s",
        stream.stream_id,
        count,
        output_pcap.exists(),
        extra={"category": "FILES"},
    )

    return output_pcap, count
