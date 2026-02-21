from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import base64
from pathlib import Path
import pyshark  # usa tshark por baixo [web:59]

@dataclass
class SdesKey:
    call_id: str
    ssrc: Optional[int]
    suite: str
    master_key: bytes
    master_salt: bytes

def _parse_crypto_line(line: str) -> tuple[str, bytes]:
    # formato típico: a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BASE64|...
    parts = line.split()
    if len(parts) < 3:
        raise ValueError(f"linha a=crypto inesperada: {line}")
    suite = parts[1]
    inline_part = [p for p in parts if p.startswith("inline:")]
    if not inline_part:
        raise ValueError(f"inline não encontrado em: {line}")
    b64 = inline_part[0].split(":", 1)[1]
    raw = base64.b64decode(b64)  # master-key + salt [web:30]
    # para AES_CM_128_HMAC_SHA1_80: 16 bytes key + 14 bytes salt = 30 bytes [web:30]
    if suite.startswith("AES_CM_128_HMAC_SHA1_80") and len(raw) >= 30:
        master_key = raw[:16]
        master_salt = raw[16:30]
    else:
        raise ValueError(f"suite não suportada ou tamanho inesperado: {suite}")
    return suite, master_key + master_salt  # devolvemos junto; split depois

def extract_sdes_keys_from_pcap(sip_pcap: Path, call_id_filter: str | None = None) -> List[SdesKey]:
    cap = pyshark.FileCapture(str(sip_pcap), display_filter="sip")

    keys: List[SdesKey] = []
    for pkt in cap:
        try:
            sip_layer = pkt.sip
        except AttributeError:
            continue

        call_id = getattr(sip_layer, "call_id", None)
        if call_id is None:
            continue
        call_id = str(call_id)
        if call_id_filter and call_id_filter not in call_id:
            continue

        try:
            sdp_text = sip_layer.msg_body
        except AttributeError:
            continue
        if not sdp_text:
            continue

        for line in str(sdp_text).splitlines():
            line = line.strip()
            if not line.startswith("a=crypto:"):
                continue
            suite, raw = _parse_crypto_line(line)
            master_key = raw[:16]
            master_salt = raw[16:30]
            keys.append(
                SdesKey(
                    call_id=call_id,
                    ssrc=None,  # pode ser preenchido mais tarde ao correlacionar com RTP
                    suite=suite,
                    master_key=master_key,
                    master_salt=master_salt,
                )
            )
    cap.close()
    if not keys:
        raise SystemExit("Não foram encontradas linhas a=crypto no PCAP SIP (SDES-SRTP).")
    return keys
