from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import base64
import logging
import time
from pathlib import Path
import pyshark  # usa tshark por baixo [web:59]
from rtphelper.logging_setup import correlation_context, short_uuid

LOGGER = logging.getLogger(__name__)

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
    start_ts = time.perf_counter()
    sip_frames = 0
    sdp_crypto_lines = 0
    cid = call_id_filter or short_uuid()
    LOGGER.info("Starting SDES extraction pcap=%s call_id_filter=%s", sip_pcap, call_id_filter or "-", extra={"category": "SDES_KEYS", "correlation_id": cid})
    cap = pyshark.FileCapture(str(sip_pcap), display_filter="sip")

    keys: List[SdesKey] = []
    with correlation_context(cid):
        try:
            for pkt in cap:
                sip_frames += 1
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

                debug_sdp_summary: list[str] = []
                for line in str(sdp_text).splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith(("m=", "c=", "a=fingerprint:", "a=setup:", "a=crypto:")):
                        debug_sdp_summary.append(line[:120])
                    if not line.startswith("a=crypto:"):
                        continue
                    sdp_crypto_lines += 1
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
                if debug_sdp_summary:
                    LOGGER.debug(
                        "SIP frame SDP summary call_id=%s fields=%s",
                        call_id,
                        " | ".join(debug_sdp_summary[:10]),
                        extra={"category": "SDP", "correlation_id": call_id},
                    )
        finally:
            cap.close()
    elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
    LOGGER.info(
        "SDES extraction completed pcap=%s sip_frames=%s crypto_lines=%s keys=%s duration_ms=%s",
        sip_pcap,
        sip_frames,
        sdp_crypto_lines,
        len(keys),
        elapsed_ms,
        extra={"category": "SDES_KEYS", "correlation_id": cid},
    )
    if not keys:
        LOGGER.warning("No SDES a=crypto lines found in SIP pcap", extra={"category": "SDES_KEYS", "correlation_id": cid})
        raise SystemExit("Não foram encontradas linhas a=crypto no PCAP SIP (SDES-SRTP).")
    return keys
