from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import PcapReader

LOGGER = logging.getLogger(__name__)

_STATUS_LINE_RE = re.compile(r"^SIP/2\.0\s+(\d{3})")


@dataclass
class SdesCryptoMaterial:
    suite: str
    master_key: bytes
    master_salt: bytes


@dataclass
class MediaSection:
    media_type: str
    port: int
    protocol: str
    payload_types: List[str] = field(default_factory=list)
    connection_ip: Optional[str] = None
    ssrcs: Set[int] = field(default_factory=set)
    sdes_cryptos: List[SdesCryptoMaterial] = field(default_factory=list)
    dtls_fingerprints: List[str] = field(default_factory=list)
    dtls_exporter_key: Optional[bytes] = None


@dataclass
class SipMessage:
    packet_number: Optional[int]
    ts: float
    src_ip: str
    dst_ip: str
    proto: str
    is_request: bool
    method: Optional[str] = None
    status_code: Optional[int] = None
    cseq_num: Optional[int] = None
    cseq_method: Optional[str] = None
    via_branch: Optional[str] = None
    to_tag: Optional[str] = None
    has_sdp: bool = False
    media_sections: List[MediaSection] = field(default_factory=list)


@dataclass
class SipCall:
    call_id: str
    media_sections: List[MediaSection] = field(default_factory=list)
    transport_tuples: Set[Tuple[str, int, str, int, str]] = field(default_factory=set)
    messages: List[SipMessage] = field(default_factory=list)


@dataclass
class SipParseResult:
    calls: Dict[str, SipCall] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


def parse_sip_pcap(pcap_path: Path) -> SipParseResult:
    if not pcap_path.exists():
        raise ValueError(f"SIP pcap not found: {pcap_path}")

    result = SipParseResult()

    with PcapReader(str(pcap_path)) as reader:
        for packet_number, packet in enumerate(reader, start=1):
            if IP not in packet:
                continue

            raw_payload = _extract_transport_payload(packet)
            if not raw_payload:
                continue

            text = raw_payload.decode("utf-8", errors="ignore")
            if "SIP/2.0" not in text:
                continue

            start_line, header_lines, headers, body = _split_message(text)
            call_id = _header_value(headers, "call-id")
            if not call_id:
                continue

            call = result.calls.setdefault(call_id, SipCall(call_id=call_id))
            tuple_value = _extract_5tuple(packet)
            if tuple_value:
                call.transport_tuples.add(tuple_value)

            ts = float(getattr(packet, "time", 0.0) or 0.0)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "udp" if UDP in packet else "tcp" if TCP in packet else "ip"
            is_request, method, status_code = _parse_start_line(start_line)
            cseq_num, cseq_method = _parse_cseq(headers.get("cseq"), header_lines)
            via_branch = _parse_via_branch(header_lines)
            to_tag = _parse_to_tag(header_lines)

            msg = SipMessage(
                packet_number=packet_number,
                ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto,
                is_request=is_request,
                method=method,
                status_code=status_code,
                cseq_num=cseq_num,
                cseq_method=cseq_method,
                via_branch=via_branch,
                to_tag=to_tag,
            )

            if body and "m=" in body:
                media_sections = _parse_sdp(body, result.warnings)
                call.media_sections.extend(media_sections)
                msg.has_sdp = True
                msg.media_sections = media_sections

            call.messages.append(msg)

    if not result.calls:
        raise ValueError("No SIP calls were found in the uploaded pcap")

    LOGGER.info(
        "Parsed SIP pcap=%s calls=%d warnings=%d",
        pcap_path,
        len(result.calls),
        len(result.warnings),
        extra={"category": "SIP"},
    )
    return result


def _extract_transport_payload(packet) -> Optional[bytes]:
    if UDP in packet and Raw in packet[UDP]:
        return bytes(packet[UDP][Raw].load)
    if TCP in packet and Raw in packet[TCP]:
        return bytes(packet[TCP][Raw].load)
    return None


def _parse_start_line(start_line: str) -> tuple[bool, Optional[str], Optional[int]]:
    # Request: "INVITE sip:... SIP/2.0"
    # Response: "SIP/2.0 200 OK"
    if start_line.startswith("SIP/2.0"):
        match = _STATUS_LINE_RE.match(start_line)
        if not match:
            return False, None, None
        try:
            return False, None, int(match.group(1))
        except ValueError:
            return False, None, None

    parts = start_line.split()
    if not parts:
        return True, None, None
    return True, parts[0].upper(), None


def _parse_cseq(cseq_header: Optional[str], header_lines: List[str]) -> tuple[Optional[int], Optional[str]]:
    # Example: "CSeq: 102 INVITE"
    value = cseq_header
    if not value:
        for line in header_lines:
            if line.lower().startswith("cseq:"):
                value = line.split(":", 1)[1].strip()
                break
    if not value:
        return None, None
    parts = value.split()
    if len(parts) < 2:
        return None, None
    try:
        return int(parts[0]), parts[1].upper()
    except ValueError:
        return None, parts[1].upper()


def _parse_via_branch(header_lines: List[str]) -> Optional[str]:
    # We want the topmost Via's branch parameter.
    via_value = None
    for line in header_lines:
        if line.lower().startswith("via:"):
            via_value = line.split(":", 1)[1].strip()
            break
    if not via_value:
        return None
    match = re.search(r"\bbranch=([^;\s]+)", via_value, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def _parse_to_tag(header_lines: List[str]) -> Optional[str]:
    to_value = None
    for line in header_lines:
        lower = line.lower()
        if lower.startswith("to:") or lower.startswith("t:"):
            to_value = line.split(":", 1)[1].strip()
            break
    if not to_value:
        return None
    match = re.search(r"\btag=([^;\s>]+)", to_value, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def _split_message(text: str) -> tuple[str, List[str], Dict[str, str], str]:
    normalized = text.replace("\r\n", "\n")
    parts = normalized.split("\n\n", 1)
    header_lines = parts[0].splitlines()
    start_line = header_lines[0].strip() if header_lines else ""
    body = parts[1] if len(parts) > 1 else ""

    headers: Dict[str, str] = {}
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        # Preserve the first occurrence (important when multiple Via headers exist).
        headers.setdefault(key, value.strip())
    return start_line, header_lines, headers, body


def _header_value(headers: Dict[str, str], header_name: str) -> Optional[str]:
    return headers.get(header_name.lower())


def _extract_5tuple(packet) -> Optional[Tuple[str, int, str, int, str]]:
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if UDP in packet:
        return (src_ip, int(packet[UDP].sport), dst_ip, int(packet[UDP].dport), "udp")
    if TCP in packet:
        return (src_ip, int(packet[TCP].sport), dst_ip, int(packet[TCP].dport), "tcp")
    return None


def _parse_sdp(sdp_body: str, warnings: List[str]) -> List[MediaSection]:
    media_sections: List[MediaSection] = []
    current: Optional[MediaSection] = None
    session_connection_ip: Optional[str] = None

    lines = [line.strip() for line in sdp_body.replace("\r", "").split("\n") if line.strip()]
    for line in lines:
        if line.startswith("c=IN IP4") or line.startswith("c=IN IP6"):
            parts = line.split()
            if len(parts) >= 3:
                if current is None:
                    session_connection_ip = parts[2]
                else:
                    current.connection_ip = parts[2]

        if line.startswith("m="):
            if current:
                media_sections.append(current)
            parts = line[2:].split()
            if len(parts) < 3:
                continue
            payloads = parts[3:] if len(parts) > 3 else []
            try:
                port = int(parts[1])
            except ValueError:
                continue
            current = MediaSection(
                media_type=parts[0],
                port=port,
                protocol=parts[2],
                payload_types=payloads,
                connection_ip=session_connection_ip,
            )
            continue

        if current is None:
            continue

        if line.startswith("a=crypto:"):
            crypto = _parse_crypto_line(line, warnings)
            if crypto:
                current.sdes_cryptos.append(crypto)
        elif line.startswith("a=fingerprint:"):
            current.dtls_fingerprints.append(line.split(":", 1)[1].strip())
        elif line.startswith("a=ssrc:"):
            ssrc = _parse_ssrc(line)
            if ssrc is not None:
                current.ssrcs.add(ssrc)
        elif line.startswith("a=dtls-srtp-key:"):
            raw = line.split(":", 1)[1].strip()
            try:
                current.dtls_exporter_key = base64.b64decode(raw)
            except Exception:
                warnings.append("Invalid a=dtls-srtp-key attribute; ignored")

    if current:
        media_sections.append(current)

    return media_sections


def _parse_crypto_line(line: str, warnings: List[str]) -> Optional[SdesCryptoMaterial]:
    parts = line.split()
    if len(parts) < 3:
        warnings.append(f"Invalid crypto line: {line}")
        return None

    suite = parts[1]
    inline = None
    for value in parts[2:]:
        if value.startswith("inline:"):
            inline = value.split(":", 1)[1].split("|", 1)[0]
            break

    if not inline:
        warnings.append(f"Crypto line missing inline key: {line}")
        return None

    try:
        raw_key = base64.b64decode(inline)
    except Exception:
        warnings.append(f"Unable to decode inline key: {line}")
        return None

    if len(raw_key) < 30:
        warnings.append(f"Crypto key material too short for suite {suite}")
        return None

    return SdesCryptoMaterial(
        suite=suite,
        master_key=raw_key[:16],
        master_salt=raw_key[16:30],
    )


def _parse_ssrc(line: str) -> Optional[int]:
    match = re.match(r"a=ssrc:(\d+)", line)
    if not match:
        return None

    try:
        return int(match.group(1))
    except ValueError:
        return None


def extract_media_endpoints_for_rtpengine_legs(call: SipCall, rtpengine_ips: Set[str]) -> tuple[Set[Tuple[str, int]], List[str]]:
    """
    Best-effort extraction of media endpoints for the "first hop" and "last hop" INVITE legs that involve the
    capture server(s) (rtpengine). This matches the desired workflow:
      - carrier -> rtpengine: INVITE to host (first hop)
      - rtpengine -> carrier: 200 OK from host (second hop)
      - core-network -> rtpengine: INVITE to host (last hop)
      - rtpengine -> core-network: 200 OK from host (last hop response)

    Because we only have SIP pcap (no SIP transaction state), we do a time-based match of INVITE to nearest 200 OK
    with swapped src/dst.
    """
    debug: List[str] = []
    endpoints: Set[Tuple[str, int]] = set()

    invites = [
        m
        for m in call.messages
        if m.is_request and m.method == "INVITE" and (m.src_ip in rtpengine_ips or m.dst_ip in rtpengine_ips)
    ]
    invites.sort(key=lambda m: m.ts)
    if not invites:
        debug.append("No INVITE messages involving capture hosts were found; using all SDP media endpoints.")
        for media in call.media_sections:
            if media.connection_ip and media.port:
                endpoints.add((media.connection_ip, media.port))
        return endpoints, debug

    legs = [invites[0]]
    if len(invites) > 1:
        legs.append(invites[-1])

    def pick_200_ok(invite: SipMessage) -> Optional[SipMessage]:
        # Prefer exact transaction matching:
        # - same CSeq number + method INVITE
        # - same Via branch (top Via)
        # - swapped direction
        # - within a short window
        def base_pred(m: SipMessage) -> bool:
            return (
                (not m.is_request)
                and m.status_code == 200
                and m.src_ip == invite.dst_ip
                and m.dst_ip == invite.src_ip
                and m.ts >= invite.ts
                and (m.ts - invite.ts) <= 120.0
            )

        candidates = [m for m in call.messages if base_pred(m)]
        candidates.sort(key=lambda m: m.ts)

        def exact(m: SipMessage) -> bool:
            if invite.cseq_num is not None and m.cseq_num is not None and invite.cseq_num != m.cseq_num:
                return False
            if invite.cseq_method and m.cseq_method and invite.cseq_method != m.cseq_method:
                return False
            if invite.via_branch and m.via_branch and invite.via_branch != m.via_branch:
                return False
            return True

        exact_hits = [m for m in candidates if exact(m)]
        if exact_hits:
            return exact_hits[0]

        # Relax: match CSeq only (branch might be missing).
        if invite.cseq_num is not None:
            cseq_hits = [m for m in candidates if m.cseq_num == invite.cseq_num and (m.cseq_method or "") == "INVITE"]
            if cseq_hits:
                return cseq_hits[0]

        # Fallback: first by time.
        return candidates[0] if candidates else None

    for idx, inv in enumerate(legs, start=1):
        ok = pick_200_ok(inv)
        debug.append(
            f"Leg {idx}: INVITE {inv.src_ip} -> {inv.dst_ip} (sdp={inv.has_sdp})"
            + (f", 200OK {ok.src_ip} -> {ok.dst_ip} (sdp={ok.has_sdp})" if ok else ", 200OK not found")
        )

        for msg in [inv, ok]:
            if msg is None:
                continue
            for media in msg.media_sections:
                if media.connection_ip and media.port:
                    endpoints.add((media.connection_ip, media.port))

    if not endpoints:
        debug.append("No endpoints found in selected legs; using all SDP media endpoints.")
        for media in call.media_sections:
            if media.connection_ip and media.port:
                endpoints.add((media.connection_ip, media.port))

    return endpoints, debug


def extract_rtpengine_media_leg_endpoints(
    call: SipCall, rtpengine_ips: Set[str]
) -> tuple[Dict[str, Set[Tuple[str, int]]], List[str]]:
    """
    Return endpoints per leg direction:
      - carrier->host (first INVITE involving rtpengine)
      - host->carrier (200 OK to that INVITE)
      - core->host (last INVITE involving rtpengine)
      - host->core (200 OK to that INVITE)

    "carrier" vs "core" are inferred by first vs last INVITE involving the capture hosts in time order.
    """
    debug: List[str] = []
    legs: Dict[str, Set[Tuple[str, int]]] = {
        "carrier->host": set(),
        "host->carrier": set(),
        "core->host": set(),
        "host->core": set(),
    }

    invites = [
        m
        for m in call.messages
        if m.is_request and m.method == "INVITE" and (m.src_ip in rtpengine_ips or m.dst_ip in rtpengine_ips)
    ]
    invites.sort(key=lambda m: m.ts)
    if not invites:
        debug.append("No INVITE messages involving capture hosts were found.")
        return legs, debug

    first_inv = invites[0]
    last_inv = invites[-1]

    def pick_200_ok(invite: SipMessage) -> Optional[SipMessage]:
        def base_pred(m: SipMessage) -> bool:
            return (
                (not m.is_request)
                and m.status_code == 200
                and m.src_ip == invite.dst_ip
                and m.dst_ip == invite.src_ip
                and m.ts >= invite.ts
                and (m.ts - invite.ts) <= 120.0
            )

        candidates = [m for m in call.messages if base_pred(m)]
        candidates.sort(key=lambda m: m.ts)

        def exact(m: SipMessage) -> bool:
            if invite.cseq_num is not None and m.cseq_num is not None and invite.cseq_num != m.cseq_num:
                return False
            if invite.cseq_method and m.cseq_method and invite.cseq_method != m.cseq_method:
                return False
            if invite.via_branch and m.via_branch and invite.via_branch != m.via_branch:
                return False
            return True

        exact_hits = [m for m in candidates if exact(m)]
        if exact_hits:
            return exact_hits[0]

        if invite.cseq_num is not None:
            cseq_hits = [m for m in candidates if m.cseq_num == invite.cseq_num and (m.cseq_method or "") == "INVITE"]
            if cseq_hits:
                return cseq_hits[0]

        return candidates[0] if candidates else None

    def endpoints_from_msg(msg: Optional[SipMessage]) -> Set[Tuple[str, int]]:
        if msg is None:
            return set()
        out: Set[Tuple[str, int]] = set()
        for media in msg.media_sections:
            if media.connection_ip and media.port:
                out.add((media.connection_ip, media.port))
        return out

    first_ok = pick_200_ok(first_inv)
    last_ok = pick_200_ok(last_inv) if last_inv is not first_inv else first_ok

    legs["carrier->host"] = endpoints_from_msg(first_inv)
    legs["host->carrier"] = endpoints_from_msg(first_ok)
    legs["core->host"] = endpoints_from_msg(last_inv)
    legs["host->core"] = endpoints_from_msg(last_ok)

    debug.append(
        "Leg carrier->host: INVITE "
        f"{first_inv.src_ip}->{first_inv.dst_ip} cseq={first_inv.cseq_num} branch={first_inv.via_branch} sdp={first_inv.has_sdp}"
    )
    debug.append(
        "Leg host->carrier: 200OK "
        f"{(first_ok.src_ip if first_ok else '?')}->{(first_ok.dst_ip if first_ok else '?')} cseq={(first_ok.cseq_num if first_ok else None)} branch={(first_ok.via_branch if first_ok else None)} sdp={(first_ok.has_sdp if first_ok else False)}"
    )
    debug.append(
        "Leg core->host: INVITE "
        f"{last_inv.src_ip}->{last_inv.dst_ip} cseq={last_inv.cseq_num} branch={last_inv.via_branch} sdp={last_inv.has_sdp}"
    )
    debug.append(
        "Leg host->core: 200OK "
        f"{(last_ok.src_ip if last_ok else '?')}->{(last_ok.dst_ip if last_ok else '?')} cseq={(last_ok.cseq_num if last_ok else None)} branch={(last_ok.via_branch if last_ok else None)} sdp={(last_ok.has_sdp if last_ok else False)}"
    )

    return legs, debug


def extract_rtp_src_filters_in_order(
    call: SipCall, capture_host_ips: Set[str]
) -> tuple[List[Dict[str, object]], List[str]]:
    """
    Implements the user-specified extraction rules (order is mandatory):

      1) RTP carrier -> host: SDP in first INVITE received (inbound, dst is capture host)
      2) RTP host -> carrier: SDP in 200 OK to that inbound INVITE
      3) RTP host -> core: SDP in first INVITE sent by host (outbound, src is capture host)
      4) RTP core -> host: SDP in 200 OK to that outbound INVITE

    For each step we extract:
      from_host = c= line associated with m=audio
      from_port = m=audio <port>

    Returns (steps, debug_lines). Each step is a dict:
      {step, leg_key, from_host, from_port, available, reason}
    """
    debug: List[str] = []

    def pick_200_ok(invite: SipMessage) -> Optional[SipMessage]:
        def base_pred(m: SipMessage) -> bool:
            return (
                (not m.is_request)
                and m.status_code == 200
                and m.src_ip == invite.dst_ip
                and m.dst_ip == invite.src_ip
                and m.ts >= invite.ts
                and (m.ts - invite.ts) <= 120.0
            )

        candidates = [m for m in call.messages if base_pred(m)]
        candidates.sort(key=lambda m: m.ts)

        def exact(m: SipMessage) -> bool:
            if invite.cseq_num is not None and m.cseq_num is not None and invite.cseq_num != m.cseq_num:
                return False
            if invite.cseq_method and m.cseq_method and invite.cseq_method != m.cseq_method:
                return False
            if invite.via_branch and m.via_branch and invite.via_branch != m.via_branch:
                return False
            return True

        exact_hits = [m for m in candidates if exact(m)]
        if exact_hits:
            return exact_hits[0]

        if invite.cseq_num is not None:
            cseq_hits = [m for m in candidates if m.cseq_num == invite.cseq_num and (m.cseq_method or "") == "INVITE"]
            if cseq_hits:
                return cseq_hits[0]

        return candidates[0] if candidates else None

    def extract_audio_from_host_port(msg: Optional[SipMessage]) -> tuple[Optional[str], Optional[int], str]:
        if msg is None:
            return None, None, "message not found"
        if not msg.media_sections:
            return None, None, "no SDP media sections in message"
        audio = next((m for m in msg.media_sections if (m.media_type or "").lower() == "audio"), None)
        if audio is None:
            return None, None, "SDP has no m=audio section"
        if not audio.connection_ip:
            return None, None, "SDP m=audio has no c= connection IP"
        if not audio.port:
            return None, None, "SDP m=audio has no RTP port"
        return audio.connection_ip, int(audio.port), ""

    invites = [m for m in call.messages if m.is_request and m.method == "INVITE"]
    invites.sort(key=lambda m: m.ts)

    inbound_inv = next((m for m in invites if m.dst_ip in capture_host_ips), None)
    outbound_inv = next((m for m in invites if m.src_ip in capture_host_ips), None)

    inbound_ok = pick_200_ok(inbound_inv) if inbound_inv else None
    outbound_ok = pick_200_ok(outbound_inv) if outbound_inv else None

    debug.append(
        f"First INVITE inbound: {(inbound_inv.src_ip + '->' + inbound_inv.dst_ip) if inbound_inv else '(none)'}"
    )
    debug.append(
        f"First INVITE outbound: {(outbound_inv.src_ip + '->' + outbound_inv.dst_ip) if outbound_inv else '(none)'}"
    )

    step_defs = [
        (1, "carrier->host", "leg_carrier_rtpengine", inbound_inv),
        (2, "host->carrier", "leg_rtpengine_carrier", inbound_ok),
        (3, "host->core", "leg_rtpengine_core", outbound_inv),
        (4, "core->host", "leg_core_rtpengine", outbound_ok),
    ]

    steps: List[Dict[str, object]] = []
    for num, _label, leg_key, msg in step_defs:
        from_host, from_port, reason = extract_audio_from_host_port(msg)
        available = from_host is not None and from_port is not None
        steps.append(
            {
                "step": num,
                "leg_key": leg_key,
                "from_host": from_host,
                "from_port": from_port,
                "available": available,
                "reason": reason,
            }
        )

    return steps, debug
