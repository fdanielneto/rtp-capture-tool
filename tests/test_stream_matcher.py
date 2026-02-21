from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import PcapWriter

from rtphelper.services.sip_parser import MediaSection, SipCall
from rtphelper.services.stream_matcher import match_streams


def test_match_streams_uses_ports_and_ssrc(tmp_path: Path) -> None:
    pcap_file = tmp_path / "media.pcap"
    writer = PcapWriter(str(pcap_file), append=False, sync=True)

    ssrc = 123456789
    rtp_header = bytes([
        0x80,
        0x60,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
    ]) + ssrc.to_bytes(4, "big")
    payload = rtp_header + b"abc"

    packet = IP(src="10.0.0.10", dst="10.0.0.20") / UDP(sport=4500, dport=4000) / Raw(load=payload)
    writer.write(packet)
    writer.close()

    call = SipCall(call_id="call-1")
    call.media_sections.append(
        MediaSection(
            media_type="audio",
            port=4000,
            protocol="RTP/SAVP",
            connection_ip="10.0.0.20",
            ssrcs={ssrc},
        )
    )

    matches = match_streams(call, {"host1": [pcap_file]})

    assert len(matches) == 1
    match = matches[0]
    assert match.src_port == 4500
    assert match.dst_port == 4000
    assert match.ssrc == ssrc
    assert pcap_file in match.source_pcaps
