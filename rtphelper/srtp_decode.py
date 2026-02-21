from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from pylibsrtp import Policy, Session
from scapy.all import PcapWriter, RawPcapReader

from rtphelper.logging_setup import correlation_context, short_uuid

LOGGER = logging.getLogger(__name__)


@dataclass
class SrtpContext:
    master_key: bytes
    master_salt: bytes


def _build_policy(ctx: SrtpContext) -> Policy:
    key = ctx.master_key + ctx.master_salt
    return Policy(key=key, ssrc_type=Policy.SSRC_ANY_INBOUND)


def decrypt_srtp_pcap(
    in_pcap: Path,
    out_pcap: Path,
    ctx: SrtpContext,
    correlation_id: str | None = None,
) -> Path:
    cid = correlation_id or short_uuid()
    start_ts = time.perf_counter()
    policy = _build_policy(ctx)
    session = Session(policy)
    reader = RawPcapReader(str(in_pcap))
    writer = PcapWriter(str(out_pcap), append=False, sync=True)

    packets_in = 0
    packets_out = 0
    decrypted_ok = 0
    decrypt_fail = 0
    short_packets = 0
    offset_mismatch = 0

    with correlation_context(cid):
        LOGGER.info("Starting SRTP decrypt input=%s output=%s", in_pcap, out_pcap, extra={"category": "SRTP_DECRYPT"})
        try:
            for raw_pkt, _meta in reader:
                packets_in += 1
                try:
                    if len(raw_pkt) <= 42:
                        short_packets += 1
                        writer.write(raw_pkt)
                        packets_out += 1
                        continue
                    version = raw_pkt[14] >> 4 if len(raw_pkt) > 14 else 0
                    if version != 4:
                        offset_mismatch += 1
                        LOGGER.debug(
                            "Fixed offset=42 may be invalid for packet_len=%s ip_version=%s",
                            len(raw_pkt),
                            version,
                            extra={"category": "SRTP_DECRYPT"},
                        )
                        writer.write(raw_pkt)
                        packets_out += 1
                        continue

                    ihl = (raw_pkt[14] & 0x0F) * 4
                    if ihl != 20:
                        offset_mismatch += 1
                        LOGGER.debug(
                            "Fixed offset=42 mismatch due to IPv4 options ihl=%s packet_len=%s",
                            ihl,
                            len(raw_pkt),
                            extra={"category": "SRTP_DECRYPT"},
                        )

                    rtp_payload = raw_pkt[42:]
                    if len(rtp_payload) < 12:
                        short_packets += 1
                        writer.write(raw_pkt)
                        packets_out += 1
                        continue

                    decrypted = session.unprotect(rtp_payload)
                    writer.write(raw_pkt[:42] + decrypted)
                    packets_out += 1
                    decrypted_ok += 1
                except Exception as exc:
                    decrypt_fail += 1
                    LOGGER.debug(
                        "SRTP decrypt failed packet_idx=%s reason=%s",
                        packets_in,
                        exc,
                        extra={"category": "SRTP_DECRYPT"},
                    )
                    writer.write(raw_pkt)
                    packets_out += 1
        finally:
            reader.close()
            writer.close()

    elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
    LOGGER.info(
        "SRTP decrypt completed input=%s output=%s packets_in=%s packets_out=%s decrypted_ok=%s decrypt_fail=%s short_packets=%s offset_mismatch=%s duration_ms=%s",
        in_pcap,
        out_pcap,
        packets_in,
        packets_out,
        decrypted_ok,
        decrypt_fail,
        short_packets,
        offset_mismatch,
        elapsed_ms,
        extra={"category": "SRTP_DECRYPT", "correlation_id": cid},
    )
    return out_pcap
