"""
SIP Correlation Service for B2BUA and RTP Engine scenarios.

This module implements improved correlation logic that handles:
- Multiple Call-IDs via X-Talkdesk-Other-Leg-Call-Id header
- RTP Engine detection by analyzing SDP c= changes across hops
- Proper identification of Carrier/Core legs based on direction
- Incomplete SDP handling (checking adjacent packets)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rtphelper.services.sip_parser import SipCall, SipMessage, SipParseResult

LOGGER = logging.getLogger(__name__)


@dataclass
class MediaEndpoint:
    """Represents an RTP media endpoint from SDP."""
    rtp_ip: str
    rtp_port: int
    packet_number: Optional[int] = None
    method: Optional[str] = None  # INVITE or 200 OK


@dataclass
class LegInfo:
    """Information about a call leg (Carrier or Core side)."""
    leg_type: str  # "carrier", "core", or "rtp_engine"
    call_ids: List[str] = field(default_factory=list)
    source_ip: str = ""
    destination_ip: str = ""
    source_media: Optional[MediaEndpoint] = None  # From INVITE
    destination_media: Optional[MediaEndpoint] = None  # From 200 OK
    invite_packet: Optional[int] = None
    ok_200_packet: Optional[int] = None
    

@dataclass
class RtpEngineInfo:
    """RTP Engine detection information."""
    detected: bool = False
    xcc_ip: Optional[str] = None  # XCC/B2BUA server IP (from SIP signaling)
    engine_ip: Optional[str] = None  # Deprecated: use xcc_ip
    engine_ips: Set[str] = field(default_factory=set)
    sdp_change_packet: Optional[int] = None
    original_sdp_ip: Optional[str] = None  # c= IP from first INVITE
    changed_sdp_ip: Optional[str] = None   # c= IP after change (RTP Engine's announced IP)


@dataclass 
class CorrelationContext:
    """Complete correlation context for a B2BUA call."""
    direction: str  # "inbound" or "outbound"
    call_ids: List[str] = field(default_factory=list)
    carrier_leg: Optional[LegInfo] = None
    core_leg: Optional[LegInfo] = None
    rtp_engine: RtpEngineInfo = field(default_factory=RtpEngineInfo)
    legs: List[LegInfo] = field(default_factory=list)
    log_lines: List[str] = field(default_factory=list)
    

def group_related_calls(parse_result: SipParseResult) -> List[Set[str]]:
    """
    Group Call-IDs that belong to the same call using X-Talkdesk-Other-Leg-Call-Id.
    
    Returns a list of sets, each set containing related Call-IDs.
    """
    all_call_ids = set(parse_result.calls.keys())
    other_leg_mapping: Dict[str, Set[str]] = {}
    
    for call_id, call in parse_result.calls.items():
        for msg in call.messages:
            if msg.other_leg_call_id:
                other_leg_mapping.setdefault(call_id, set()).add(msg.other_leg_call_id)
                other_leg_mapping.setdefault(msg.other_leg_call_id, set()).add(call_id)
    
    # Build connected components
    visited: Set[str] = set()
    groups: List[Set[str]] = []
    
    def dfs(call_id: str, group: Set[str]) -> None:
        if call_id in visited:
            return
        visited.add(call_id)
        if call_id in all_call_ids:
            group.add(call_id)
        for related in other_leg_mapping.get(call_id, set()):
            dfs(related, group)
    
    for call_id in all_call_ids:
        if call_id not in visited:
            group: Set[str] = set()
            dfs(call_id, group)
            if group:
                groups.append(group)
    
    return groups


def merge_calls_by_group(parse_result: SipParseResult, group: Set[str]) -> SipCall:
    """
    Merge multiple SipCall objects into a single virtual call for correlation.
    
    Messages are combined and sorted by timestamp.
    """
    if len(group) == 1:
        call_id = next(iter(group))
        return parse_result.calls[call_id]
    
    # Create merged call
    merged_call_id = ";".join(sorted(group))
    merged = SipCall(call_id=merged_call_id)
    
    for call_id in group:
        if call_id in parse_result.calls:
            call = parse_result.calls[call_id]
            merged.messages.extend(call.messages)
            merged.media_sections.extend(call.media_sections)
            merged.transport_tuples.update(call.transport_tuples)
    
    # Sort messages by timestamp
    merged.messages.sort(key=lambda m: (m.ts, m.packet_number or 0))
    
    return merged


def detect_rtp_engine(call: SipCall, direction: str) -> RtpEngineInfo:
    """
    Detect RTP Engine presence by analyzing SDP c= line changes across INVITE hops.
    
    RTP Engine is identified when a message relays an INVITE but changes the c= IP
    in the SDP to a different value.
    """
    info = RtpEngineInfo()
    
    # Get all INVITEs sorted by timestamp
    invites = sorted(
        [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"],
        key=lambda m: m.ts
    )
    
    if not invites:
        return info
    
    # Track SDP c= IPs as INVITE propagates
    first_invite = invites[0]
    first_rtp_ip = _extract_audio_connection_ip(first_invite)
    
    if not first_rtp_ip:
        return info
    
    # Check subsequent INVITEs for c= changes
    for idx, invite in enumerate(invites[1:], start=1):
        rtp_ip = _extract_audio_connection_ip(invite)
        if rtp_ip and rtp_ip != first_rtp_ip:
            # RTP IP changed - the source of this INVITE is the XCC (that announces RTP Engine)
            info.detected = True
            info.xcc_ip = invite.src_ip
            info.engine_ip = invite.src_ip  # Deprecated, kept for compatibility
            info.engine_ips.add(invite.src_ip)
            info.sdp_change_packet = invite.packet_number
            info.original_sdp_ip = first_rtp_ip
            info.changed_sdp_ip = rtp_ip
            LOGGER.debug(
                "RTP Engine detected at packet=%s: c= changed from %s to %s, xcc_ip=%s",
                invite.packet_number,
                first_rtp_ip,
                rtp_ip,
                invite.src_ip,
                extra={"category": "SIP_CORRELATION"},
            )
            break
    
    return info


def _extract_audio_connection_ip(msg: SipMessage) -> Optional[str]:
    """Extract the c= connection IP from m=audio section."""
    if not msg.has_sdp or not msg.media_sections:
        return None
    for section in msg.media_sections:
        if (section.media_type or "").lower() == "audio" and section.connection_ip:
            return section.connection_ip
    return None


def _extract_audio_port(msg: SipMessage) -> Optional[int]:
    """Extract the m=audio port."""
    if not msg.has_sdp or not msg.media_sections:
        return None
    for section in msg.media_sections:
        if (section.media_type or "").lower() == "audio" and section.port:
            return section.port
    return None


def _find_adjacent_invite_with_sdp(call: SipCall, invite: SipMessage) -> Optional[SipMessage]:
    """
    When an INVITE lacks SDP info, check adjacent packets (same source host)
    for an INVITE with valid SDP.
    
    Priority: previous packet first, then next packet.
    """
    if invite.packet_number is None:
        return None
    
    by_packet = {m.packet_number: m for m in call.messages if m.packet_number is not None}
    
    # Check previous packet first (requirement: same source)
    prev_pkt = by_packet.get(invite.packet_number - 1)
    if (prev_pkt 
        and prev_pkt.is_request 
        and (prev_pkt.method or "").upper() == "INVITE"
        and prev_pkt.src_ip == invite.src_ip
        and prev_pkt.has_sdp 
        and prev_pkt.media_sections):
        return prev_pkt
    
    # Check next packet (requirement: same source)
    next_pkt = by_packet.get(invite.packet_number + 1)
    if (next_pkt 
        and next_pkt.is_request 
        and (next_pkt.method or "").upper() == "INVITE"
        and next_pkt.src_ip == invite.src_ip
        and next_pkt.has_sdp 
        and next_pkt.media_sections):
        return next_pkt
    
    return None


def _find_adjacent_200ok_with_sdp(call: SipCall, ok: SipMessage) -> Optional[SipMessage]:
    """
    When a 200 OK lacks SDP info, check adjacent packets (same source host)
    for a 200 OK with valid SDP.
    
    Priority: previous packet first, then next packet.
    """
    if ok.packet_number is None:
        return None
    
    by_packet = {m.packet_number: m for m in call.messages if m.packet_number is not None}
    
    # Check previous packet first
    prev_pkt = by_packet.get(ok.packet_number - 1)
    if (prev_pkt
        and not prev_pkt.is_request
        and prev_pkt.status_code == 200
        and prev_pkt.src_ip == ok.src_ip
        and prev_pkt.has_sdp
        and _extract_audio_port(prev_pkt) is not None):
        return prev_pkt
    
    # Check next packet
    next_pkt = by_packet.get(ok.packet_number + 1)
    if (next_pkt
        and not next_pkt.is_request
        and next_pkt.status_code == 200
        and next_pkt.src_ip == ok.src_ip
        and next_pkt.has_sdp
        and _extract_audio_port(next_pkt) is not None):
        return next_pkt
    
    return None


def _find_200ok_for_invite(call: SipCall, invite: SipMessage) -> Optional[SipMessage]:
    """Find the 200 OK response matching an INVITE."""
    candidates = [
        m for m in call.messages
        if (not m.is_request
            and m.status_code == 200
            and m.src_ip == invite.dst_ip
            and m.dst_ip == invite.src_ip
            and m.ts >= invite.ts
            and (m.ts - invite.ts) <= 180.0)
    ]
    candidates.sort(key=lambda m: m.ts)
    
    # Try exact match first (CSeq + Via branch)
    for m in candidates:
        if invite.cseq_num is not None and m.cseq_num is not None:
            if invite.cseq_num != m.cseq_num:
                continue
        if invite.via_branch and m.via_branch:
            if invite.via_branch != m.via_branch:
                continue
        return m
    
    # Fallback to first candidate
    return candidates[0] if candidates else None


def _find_invite_to_engine(call: SipCall, engine_ip: str, after_ts: float) -> Optional[SipMessage]:
    """Find first INVITE sent to RTP engine after a reference timestamp."""
    candidates = [
        m
        for m in call.messages
        if (
            m.is_request
            and (m.method or "").upper() == "INVITE"
            and m.dst_ip == engine_ip
            and m.ts >= after_ts
        )
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda m: m.ts)
    return candidates[0]


def _find_last_invite_for_tag(call: SipCall, from_tag: str) -> Optional[SipMessage]:
    """
    Find the last INVITE that shares the same from_tag.
    This helps identify the final hop in a single Call-ID B2BUA scenario.
    
    Note: In multi-Call-ID scenarios, use _find_last_initial_invite instead.
    """
    matching = [
        m for m in call.messages
        if m.is_request 
        and (m.method or "").upper() == "INVITE"
        and m.from_tag == from_tag
    ]
    if not matching:
        return None
    matching.sort(key=lambda m: m.ts)
    return matching[-1]


def _find_last_initial_invite(call: SipCall) -> Optional[SipMessage]:
    """
    Find the last initial INVITE in a call flow.
    
    An initial INVITE is identified by having NO to_tag in the To header.
    This is the definitive way to identify initial INVITEs vs re-INVITEs or
    in-dialog requests.
    
    In B2BUA scenarios with multiple Call-IDs, this correctly identifies
    the final INVITE that reaches the ultimate destination.
    
    Returns the last INVITE without a to_tag, sorted by timestamp.
    """
    # Get all INVITEs without to_tag (initial INVITEs only)
    initial_invites = [
        m for m in call.messages
        if m.is_request 
        and (m.method or "").upper() == "INVITE"
        and not m.to_tag  # No to_tag means it's an initial INVITE
    ]
    
    if not initial_invites:
        return None
    
    # Sort by timestamp and return the last one
    initial_invites.sort(key=lambda m: m.ts)
    return initial_invites[-1]


def build_correlation_context(
    call: SipCall,
    direction: str,
    all_call_ids: List[str],
) -> CorrelationContext:
    """
    Build complete correlation context for a B2BUA call.
    
    Args:
        call: The SipCall (potentially merged from multiple Call-IDs)
        direction: "inbound" or "outbound"
        all_call_ids: List of all Call-IDs in this call group
        
    Returns:
        CorrelationContext with carrier/core leg information
    """
    ctx = CorrelationContext(direction=direction, call_ids=all_call_ids)
    
    # Get all INVITEs sorted by timestamp
    invites = sorted(
        [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"],
        key=lambda m: m.ts
    )
    
    if not invites:
        ctx.log_lines.append("ERROR: No INVITE found in SIP pcap")
        return ctx
    
    # Detect RTP Engine
    ctx.rtp_engine = detect_rtp_engine(call, direction)
    
    # Find first INVITE (with SDP if possible)
    first_invite = invites[0]
    invites_with_sdp = [m for m in invites if m.has_sdp and m.media_sections]
    if invites_with_sdp:
        first_invite = invites_with_sdp[0]
    
    # Handle incomplete SDP
    if not _extract_audio_port(first_invite):
        adj = _find_adjacent_invite_with_sdp(call, first_invite)
        if adj:
            ctx.log_lines.append(
                f"INFO: First INVITE packet {first_invite.packet_number} has no SDP, "
                f"using adjacent INVITE packet {adj.packet_number}"
            )
            first_invite = adj
    
    # Determine Source and Destination IPs
    # Direction affects interpretation:
    # - Inbound: first INVITE comes from Carrier
    # - Outbound: first INVITE comes from Core
    source_ip = first_invite.src_ip
    first_destination_ip = first_invite.dst_ip
    
    # Find the last initial INVITE (no to_tag = initial INVITE, not re-INVITE)
    # This correctly handles multi-Call-ID B2BUA scenarios where from_tag changes
    last_invite = first_invite
    final = _find_last_initial_invite(call)
    if final and final.packet_number != first_invite.packet_number:
        last_invite = final
        ctx.log_lines.append(
            f"INFO: INVITE propagated across hops, last hop at packet {final.packet_number} "
            f"(identified by last INVITE without to_tag)"
        )
    
    # The Destination IP is where the last INVITE lands
    final_destination_ip = last_invite.dst_ip
    
    # Find 200 OK for the last INVITE (from destination)
    ok_for_last = _find_200ok_for_invite(call, last_invite)
    if ok_for_last and not _extract_audio_port(ok_for_last):
        adj_ok = _find_adjacent_200ok_with_sdp(call, ok_for_last)
        if adj_ok:
            ctx.log_lines.append(
                f"INFO: 200 OK packet {ok_for_last.packet_number} has no SDP, "
                f"using adjacent 200 OK packet {adj_ok.packet_number}"
            )
            ok_for_last = adj_ok
    
    # Build carrier/core legs based on direction
    if direction == "inbound":
        # Inbound: Carrier -> RTP Engine (optional) -> Core
        carrier_ip = source_ip
        core_ip = final_destination_ip
    else:
        # Outbound: Core -> RTP Engine (optional) -> Carrier
        core_ip = source_ip
        carrier_ip = final_destination_ip
    engine_ip = ctx.rtp_engine.engine_ip if ctx.rtp_engine.detected else None
    
    # Build Carrier leg
    carrier_leg = LegInfo(
        leg_type="carrier",
        call_ids=all_call_ids,
        source_ip=carrier_ip,
        destination_ip=(
            engine_ip if (direction == "inbound" and engine_ip) else final_destination_ip
        ),
    )
    
    # Get carrier media from first INVITE and its 200 OK
    if direction == "inbound":
        # For inbound, carrier media is from the first INVITE (carrier sends INVITE)
        carrier_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(first_invite) or "",
            rtp_port=_extract_audio_port(first_invite) or 0,
            packet_number=first_invite.packet_number,
            method="INVITE",
        )
        # Find 200 OK going back to carrier.
        # If RTP engine is present, prefer the 200 OK of the INVITE entering engine.
        carrier_ok = None
        if engine_ip:
            invite_to_engine = _find_invite_to_engine(call, engine_ip, first_invite.ts)
            if invite_to_engine:
                carrier_ok = _find_200ok_for_invite(call, invite_to_engine)
        if carrier_ok is None:
            carrier_ok = _find_200ok_for_invite(call, first_invite)
        if carrier_ok:
            if not _extract_audio_port(carrier_ok):
                adj = _find_adjacent_200ok_with_sdp(call, carrier_ok)
                if adj:
                    carrier_ok = adj
            carrier_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(carrier_ok) or "",
                rtp_port=_extract_audio_port(carrier_ok) or 0,
                packet_number=carrier_ok.packet_number,
                method="200 OK",
            )
            carrier_leg.ok_200_packet = carrier_ok.packet_number
        carrier_leg.invite_packet = first_invite.packet_number
    else:
        # For outbound, carrier media is from the INVITE to carrier and its 200 OK
        # Find first INVITE to carrier (last hop)
        carrier_invite = last_invite
        carrier_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(carrier_invite) or "",
            rtp_port=_extract_audio_port(carrier_invite) or 0,
            packet_number=carrier_invite.packet_number,
            method="INVITE",
        )
        carrier_ok = _find_200ok_for_invite(call, carrier_invite)
        if carrier_ok:
            if not _extract_audio_port(carrier_ok):
                adj = _find_adjacent_200ok_with_sdp(call, carrier_ok)
                if adj:
                    carrier_ok = adj
            carrier_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(carrier_ok) or "",
                rtp_port=_extract_audio_port(carrier_ok) or 0,
                packet_number=carrier_ok.packet_number,
                method="200 OK",
            )
            carrier_leg.ok_200_packet = carrier_ok.packet_number
        carrier_leg.invite_packet = carrier_invite.packet_number
    
    # Build Core leg
    core_leg = LegInfo(
        leg_type="core",
        call_ids=all_call_ids,
        source_ip=(
            engine_ip if (direction == "inbound" and engine_ip) else core_ip
        ),
        destination_ip=(
            core_ip if (direction == "inbound" and engine_ip) else source_ip
        ),
    )
    
    if direction == "outbound":
        # For outbound, core media is from first INVITE (core sends) and its 200 OK
        core_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(first_invite) or "",
            rtp_port=_extract_audio_port(first_invite) or 0,
            packet_number=first_invite.packet_number,
            method="INVITE",
        )
        core_ok = ok_for_last  # 200 OK comes from the final destination
        if core_ok:
            core_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(core_ok) or "",
                rtp_port=_extract_audio_port(core_ok) or 0,
                packet_number=core_ok.packet_number,
                method="200 OK",
            )
            core_leg.ok_200_packet = core_ok.packet_number
        core_leg.invite_packet = first_invite.packet_number
    else:
        # For inbound, core media is from the INVITE TO core (last hop) and its 200 OK
        core_invite = last_invite
        core_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(core_invite) or "",
            rtp_port=_extract_audio_port(core_invite) or 0,
            packet_number=core_invite.packet_number,
            method="INVITE",
        )
        core_ok = ok_for_last
        if core_ok:
            core_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(core_ok) or "",
                rtp_port=_extract_audio_port(core_ok) or 0,
                packet_number=core_ok.packet_number,
                method="200 OK",
            )
            core_leg.ok_200_packet = core_ok.packet_number
        core_leg.invite_packet = core_invite.packet_number
    
    ctx.carrier_leg = carrier_leg
    ctx.core_leg = core_leg
    ctx.legs = [carrier_leg, core_leg]
    
    # Add structured log output
    _add_structured_logs(ctx)
    
    return ctx


def _add_structured_logs(ctx: CorrelationContext) -> None:
    """Add structured log lines to correlation context."""
    ctx.log_lines.append("")
    ctx.log_lines.append(_format_log_banner("SIP CORRELATION ANALYSIS"))
    ctx.log_lines.append(f"Direction: {ctx.direction.upper()}")
    ctx.log_lines.append(f"CallID(s): {'; '.join(ctx.call_ids)}")
    
    if ctx.rtp_engine.detected:
        ctx.log_lines.append(f"RTP ENGINE: YES (XCC IP: {ctx.rtp_engine.xcc_ip})")
    else:
        ctx.log_lines.append("RTP ENGINE: NO")
    
    ctx.log_lines.append("")
    
    # Log Carrier leg
    if ctx.carrier_leg:
        leg = ctx.carrier_leg
        ctx.log_lines.append("-" * 25)
        if ctx.rtp_engine.detected:
            ctx.log_lines.append("LEG: CARRIER - RTP ENGINE")
        else:
            ctx.log_lines.append("LEG: CARRIER")
        ctx.log_lines.append(f"  SRC IP: {leg.source_ip}")
        ctx.log_lines.append(f"  DST IP: {leg.destination_ip}")
        if leg.source_media:
            ctx.log_lines.append(f"  INVITE (packet {leg.source_media.packet_number}):")
            ctx.log_lines.append(f"    RTP IP: {leg.source_media.rtp_ip}")
            ctx.log_lines.append(f"    RTP Port: {leg.source_media.rtp_port}")
        if leg.destination_media:
            ctx.log_lines.append(f"  200 OK (packet {leg.destination_media.packet_number}):")
            ctx.log_lines.append(f"    RTP IP: {leg.destination_media.rtp_ip}")
            ctx.log_lines.append(f"    RTP Port: {leg.destination_media.rtp_port}")
    
    # Log Core leg
    if ctx.core_leg:
        leg = ctx.core_leg
        ctx.log_lines.append("-" * 25)
        if ctx.rtp_engine.detected:
            ctx.log_lines.append("LEG: RTP ENGINE - CORE")
        else:
            ctx.log_lines.append("LEG: CORE")
        ctx.log_lines.append(f"  SRC IP: {leg.source_ip}")
        ctx.log_lines.append(f"  DST IP: {leg.destination_ip}")
        if leg.source_media:
            ctx.log_lines.append(f"  INVITE (packet {leg.source_media.packet_number}):")
            ctx.log_lines.append(f"    RTP IP: {leg.source_media.rtp_ip}")
            ctx.log_lines.append(f"    RTP Port: {leg.source_media.rtp_port}")
        if leg.destination_media:
            ctx.log_lines.append(f"  200 OK (packet {leg.destination_media.packet_number}):")
            ctx.log_lines.append(f"    RTP IP: {leg.destination_media.rtp_ip}")
            ctx.log_lines.append(f"    RTP Port: {leg.destination_media.rtp_port}")
        ctx.log_lines.append("-" * 25)


def _format_log_banner(text: str, width: int = 67) -> str:
    """Build a centered banner line with fixed width."""
    label = f"  {str(text).strip()}  "
    if len(label) >= width:
        return label
    pad = width - len(label)
    left = pad // 2
    right = pad - left
    return f"{'=' * left}{label}{'=' * right}"
    
    ctx.log_lines.append("-" * 40)
    ctx.log_lines.append("")


def build_tshark_filters(ctx: CorrelationContext, rtpengine_actual_ip: Optional[str] = None, for_count: bool = False) -> List[Dict[str, Any]]:
    """
    Build tshark filter expressions from correlation context.
    
    Args:
        ctx: Correlation context with carrier/core leg information
        rtpengine_actual_ip: Actual RTP Engine IP detected from PCAP (replaces SDP-announced IP)
        for_count: If True, omit ip.src==rtpengine_ip (used in Phase 1 count before actual IP is known)
    
    Returns a list of filter steps, each with:
    - step: step number
    - leg_key: identifier for the leg
    - available: whether filter can be applied
    - tshark_filter: the filter expression
    - reason: why unavailable (if not available)
    """
    filters: List[Dict[str, Any]] = []
    
    if not ctx.carrier_leg or not ctx.core_leg:
        return filters
    
    carrier = ctx.carrier_leg
    core = ctx.core_leg
    
    # Helper function to get the correct IP (actual detected vs announced in SDP)
    def get_rtpengine_ip_for_filter(sdp_ip: str) -> str:
        """
        Returns the RTP Engine IP to use in filters.
        If rtpengine_actual_ip is provided and sdp_ip matches the changed_sdp_ip
        (the IP announced by RTP Engine), use the actual IP detected from PCAP.
        """
        if (rtpengine_actual_ip 
            and ctx.rtp_engine.detected 
            and ctx.rtp_engine.changed_sdp_ip 
            and sdp_ip == ctx.rtp_engine.changed_sdp_ip):
            return rtpengine_actual_ip
        return sdp_ip
    
    # Step 1: carrier -> host (RTP from carrier)
    # Filter: ip.src == carrier_rtp_ip && udp.srcport == carrier_port
    if carrier.source_media and carrier.destination_media:
        if carrier.source_media.rtp_ip and carrier.source_media.rtp_port:
            # Source is carrier IP and port from INVITE
            filters.append({
                "step": 1,
                "leg": "carrier->host",
                "leg_key": "leg_carrier_rtpengine",
                "available": True,
                "tshark_filter": f"ip.src=={carrier.source_media.rtp_ip} && udp.srcport=={carrier.source_media.rtp_port}",
                "reason": None,
            })
        else:
            filters.append({
                "step": 1,
                "leg": "carrier->host",
                "leg_key": "leg_carrier_rtpengine",
                "available": False,
                "tshark_filter": None,
                "reason": "missing carrier media info",
            })
    else:
        filters.append({
            "step": 1,
            "leg": "carrier->host",
            "leg_key": "leg_carrier_rtpengine",
            "available": False,
            "tshark_filter": None,
            "reason": "missing carrier leg media",
        })
    
    # Step 2: host -> carrier (RTP Engine to carrier)
    # Phase 1 count (for_count=True): udp.srcport && ip.dst (omit ip.src - not yet detected)
    # Phase 2 extract (for_count=False): ip.src && udp.srcport (omit ip.dst - redundant)
    if carrier.source_media and carrier.destination_media:
        if carrier.destination_media.rtp_ip and carrier.destination_media.rtp_port and carrier.source_media.rtp_ip:
            if for_count:
                # Phase 1 count: don't filter by RTP Engine IP (not yet detected)
                filter_expr = f"udp.srcport=={carrier.destination_media.rtp_port} && ip.dst=={carrier.source_media.rtp_ip}"
            else:
                # Phase 2 extract: use actual RTP Engine IP, omit destination IP
                rtpengine_ip = get_rtpengine_ip_for_filter(carrier.destination_media.rtp_ip)
                filter_expr = f"ip.src=={rtpengine_ip} && udp.srcport=={carrier.destination_media.rtp_port}"
            
            filters.append({
                "step": 2,
                "leg": "host->carrier",
                "leg_key": "leg_rtpengine_carrier",
                "available": True,
                "tshark_filter": filter_expr,
                "reason": None,
            })
        else:
            filters.append({
                "step": 2,
                "leg": "host->carrier",
                "leg_key": "leg_rtpengine_carrier",
                "available": False,
                "tshark_filter": None,
                "reason": "missing carrier media info",
            })
    else:
        filters.append({
            "step": 2,
            "leg": "host->carrier",
            "leg_key": "leg_rtpengine_carrier",
            "available": False,
            "tshark_filter": None,
            "reason": "missing carrier source media",
        })
    
    # Step 3: host -> core (RTP Engine to core)
    # Phase 1 count (for_count=True): udp.srcport && ip.dst (omit ip.src - not yet detected)
    # Phase 2 extract (for_count=False): ip.src && udp.srcport (omit ip.dst - redundant)
    if core.source_media and core.destination_media:
        if core.source_media.rtp_ip and core.source_media.rtp_port and core.destination_media.rtp_ip:
            if for_count:
                # Phase 1 count: don't filter by RTP Engine IP (not yet detected)
                filter_expr = f"udp.srcport=={core.source_media.rtp_port} && ip.dst=={core.destination_media.rtp_ip}"
            else:
                # Phase 2 extract: use actual RTP Engine IP, omit destination IP
                rtpengine_ip = get_rtpengine_ip_for_filter(core.source_media.rtp_ip)
                filter_expr = f"ip.src=={rtpengine_ip} && udp.srcport=={core.source_media.rtp_port}"
        else:
            filter_expr = None
        
        if filter_expr:
            filters.append({
                "step": 3,
                "leg": "host->core",
                "leg_key": "leg_rtpengine_core",
                "available": True,
                "tshark_filter": filter_expr,
                "reason": None,
            })
        else:
            filters.append({
                "step": 3,
                "leg": "host->core",
                "leg_key": "leg_rtpengine_core",
                "available": False,
                "tshark_filter": None,
                "reason": "missing core media info",
            })
    else:
        filters.append({
            "step": 3,
            "leg": "host->core",
            "leg_key": "leg_rtpengine_core",
            "available": False,
            "tshark_filter": None,
            "reason": "missing core leg media",
        })
    
    # Step 4: core -> host (RTP from core)
    # Filter: ip.src == core_ip && udp.srcport == core_port
    if core.source_media and core.destination_media:
        if core.destination_media.rtp_ip and core.destination_media.rtp_port:
            # Core's IP and port from 200 OK
            filter_expr = f"ip.src=={core.destination_media.rtp_ip} && udp.srcport=={core.destination_media.rtp_port}"
        else:
            filter_expr = None
        
        if filter_expr:
            filters.append({
                "step": 4,
                "leg": "core->host",
                "leg_key": "leg_core_rtpengine",
                "available": True,
                "tshark_filter": filter_expr,
                "reason": None,
            })
        else:
            filters.append({
                "step": 4,
                "leg": "core->host",
                "leg_key": "leg_core_rtpengine",
                "available": False,
                "tshark_filter": None,
                "reason": "missing core media info",
            })
    else:
        filters.append({
            "step": 4,
            "leg": "core->host",
            "leg_key": "leg_core_rtpengine",
            "available": False,
            "tshark_filter": None,
            "reason": "missing core leg media",
        })
    
    return filters


def detect_rtpengine_ip_from_pcap(
    pcap_file: Path,
    *,
    carrier_ips: Set[str],
    core_ips: Set[str],
    max_packets: int = 5,
) -> Optional[str]:
    """
    Detect the actual RTP Engine IP from a capture PCAP file.
    
    Analyzes the first few packets to find the common IP that appears as src or dst,
    excluding known carrier and core IPs. This IP is the RTP Engine's actual IP
    in the capture (which may differ from the public IP announced in SDP).
    
    Args:
        pcap_file: Path to the captured PCAP file
        carrier_ips: Set of known carrier IP addresses to exclude
        core_ips: Set of known core IP addresses to exclude
        max_packets: Maximum number of packets to analyze
        
    Returns:
        The detected RTP Engine IP, or None if detection fails
    """
    if not pcap_file.exists():
        return None
    
    try:
        from collections import Counter
        from scapy.layers.inet import IP, UDP
        from scapy.packet import Raw
        from scapy.utils import PcapReader
        
        ip_counter = Counter()
        known_ips = carrier_ips | core_ips
        
        with PcapReader(str(pcap_file)) as reader:
            for idx, pkt in enumerate(reader):
                if idx >= max_packets:
                    break
                    
                if IP not in pkt or UDP not in pkt:
                    continue
                
                # Check if it's an RTP packet (basic validation)
                if Raw in pkt[UDP]:
                    payload = bytes(pkt[UDP][Raw].load)
                    if len(payload) >= 12 and (payload[0] >> 6) == 2:
                        # Valid RTP packet, count IPs
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        
                        # Only count IPs that are not carrier/core
                        if src_ip not in known_ips:
                            ip_counter[src_ip] += 1
                        if dst_ip not in known_ips:
                            ip_counter[dst_ip] += 1
        
        # Return the most common IP (should be RTP Engine)
        if ip_counter:
            most_common_ip, count = ip_counter.most_common(1)[0]
            LOGGER.debug(
                "Detected RTP Engine IP from PCAP file=%s ip=%s occurrences=%s",
                pcap_file.name,
                most_common_ip,
                count,
                extra={"category": "SIP_CORRELATION"},
            )
            return most_common_ip
            
    except Exception as exc:
        LOGGER.warning(
            "Failed to detect RTP Engine IP from PCAP file=%s error=%s",
            pcap_file.name,
            exc,
            extra={"category": "SIP_CORRELATION"},
        )
    
    return None


def correlate_sip_call(
    parse_result: SipParseResult,
    direction: str,
    primary_call_id: Optional[str] = None,
) -> Tuple[CorrelationContext, SipCall]:
    """
    Main entry point for SIP correlation.
    
    Args:
        parse_result: Parsed SIP pcap result
        direction: "inbound" or "outbound"
        primary_call_id: Optional specific Call-ID to focus on
        
    Returns:
        Tuple of (CorrelationContext, merged SipCall)
    """
    # Group related calls
    groups = group_related_calls(parse_result)
    
    # Find the group containing primary_call_id, or use largest group
    target_group: Set[str] = set()
    if primary_call_id:
        for group in groups:
            if primary_call_id in group:
                target_group = group
                break
    
    if not target_group and groups:
        # Use the group with most messages
        target_group = max(groups, key=lambda g: sum(
            len(parse_result.calls[cid].messages) 
            for cid in g if cid in parse_result.calls
        ))
    
    if not target_group:
        # Fallback to all calls
        target_group = set(parse_result.calls.keys())
    
    # Merge calls in group
    merged_call = merge_calls_by_group(parse_result, target_group)
    
    # Build correlation context
    all_call_ids = sorted(target_group)
    ctx = build_correlation_context(merged_call, direction, all_call_ids)
    
    return ctx, merged_call
