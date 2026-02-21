from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import struct
from pylibsrtp import Policy, Session  # bindings para libsrtp [web:44][web:49]
from scapy.all import RawPcapReader, PcapWriter  # para manipular PCAP rapidamente

@dataclass
class SrtpContext:
    master_key: bytes
    master_salt: bytes

def _build_policy(ctx: SrtpContext) -> Policy:
    # libsrtp espera key (master key + salt) num único blob [web:49][web:60]
    key = ctx.master_key + ctx.master_salt
    p = Policy(key=key, ssrc_type=Policy.SSRC_ANY_INBOUND)
    return p

def decrypt_srtp_pcap(
    in_pcap: Path,
    out_pcap: Path,
    ctx: SrtpContext,
) -> Path:
    policy = _build_policy(ctx)
    session = Session(policy)
    reader = RawPcapReader(str(in_pcap))
    writer = PcapWriter(str(out_pcap), append=False, sync=True)

    for raw_pkt, meta in reader:
        # isto é simplista: assume UDP/IP/ETH; para produção podes usar Scapy para parse completo
        # e só tentar SRTP em payloads UDP com portas RTP típicas
        try:
            # salto ethernet(14) + IP(20) + UDP(8) = 42 bytes (sem opções IP)
            rtp_payload = raw_pkt[42:]
            if len(rtp_payload) < 12:
                writer.write(raw_pkt)
                continue
            decrypted = session.unprotect(rtp_payload)
            # re-inject decrypted RTP no mesmo frame substituindo payload
            new_pkt = raw_pkt[:42] + decrypted
            writer.write(new_pkt)
        except Exception:
            # se falhar, escreve original (pode não ser SRTP/RTP)
            writer.write(raw_pkt)

    reader.close()
    writer.close()
    return out_pcap
