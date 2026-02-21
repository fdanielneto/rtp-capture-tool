import base64
from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import PcapWriter

from rtphelper.services.sip_parser import parse_sip_pcap


def test_parse_sip_pcap_extracts_sdes_crypto(tmp_path: Path) -> None:
    raw = bytes(range(30))
    inline = base64.b64encode(raw).decode("ascii")

    sip_message = (
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060\r\n"
        "Call-ID: test-call-id\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 200\r\n"
        "\r\n"
        "v=0\r\n"
        "o=- 1 1 IN IP4 10.0.0.1\r\n"
        "s=-\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 4000 RTP/SAVP 0\r\n"
        f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{inline}\r\n"
        "a=ssrc:11223344 cname:test\r\n"
    )

    pcap_file = tmp_path / "sip.pcap"
    writer = PcapWriter(str(pcap_file), append=False, sync=True)
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5060, dport=5060) / Raw(load=sip_message.encode("utf-8"))
    writer.write(packet)
    writer.close()

    result = parse_sip_pcap(pcap_file)
    assert "test-call-id" in result.calls
    call = result.calls["test-call-id"]
    assert len(call.media_sections) == 1
    media = call.media_sections[0]
    assert media.port == 4000
    assert media.sdes_cryptos[0].master_key == raw[:16]
    assert media.sdes_cryptos[0].master_salt == raw[16:30]
    assert 11223344 in media.ssrcs
