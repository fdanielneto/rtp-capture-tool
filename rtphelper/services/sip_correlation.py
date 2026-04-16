"""
SIP Correlation Service for B2BUA and RTP Engine scenarios.

This module implements improved correlation logic that handles:
- Multiple Call-IDs via X-Talkdesk-Other-Leg-Call-Id header
- RTP Engine detection by analyzing SDP c= changes across hops
- Proper identification of Carrier/Core legs based on direction
- Incomplete SDP handling (checking adjacent packets)
- Dynamic correlation case loading from YAML configuration files
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from rtphelper.services.sip_parser import SipCall, SipMessage, SipParseResult
from rtphelper.services.correlation_case_loader import (
    get_loader,
    CorrelationCase,
    reload_cases,
)

# Import strategy and template loaders (new modular architecture)
try:
    from rtphelper.services.correlation_strategy_loader import (
        CorrelationStrategyLoader,
        CorrelationStrategy as StrategyConfig,
        get_strategy as get_strategy_config,
    )
    from rtphelper.services.filter_template_loader import (
        FilterTemplateLoader,  
        FilterTemplate,
        get_template as get_filter_template,
    )
    MODULAR_ARCHITECTURE_AVAILABLE = True
except ImportError:
    LOGGER.warning("Modular architecture (strategy/template loaders) not available, using legacy config")
    MODULAR_ARCHITECTURE_AVAILABLE = False

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
    use_case: Optional[str] = None
    filter_template_name: Optional[str] = None
    expected_legs: Optional[int] = None


# ==============================================================================
# Use-Case Based Correlation Strategy Pattern
# ==============================================================================

class CorrelationStrategy(ABC):
    """
    Abstract base class for correlation strategies.
    
    Each strategy implements correlation logic for a specific use case
    (e.g., Inbound PSTN, Outbound PSTN, SIP Trunk, etc.).
    """
    
    @abstractmethod
    def correlate(
        self,
        call: SipCall,
        direction: str,
        all_call_ids: List[str],
    ) -> CorrelationContext:
        """
        Build correlation context for a specific use case.
        
        Args:
            call: The SipCall (potentially merged from multiple Call-IDs)
            direction: "inbound" or "outbound"
            all_call_ids: List of all Call-IDs in this call group
            
        Returns:
            CorrelationContext with carrier/core leg information
        """
        pass


def identify_use_case(call: SipCall, direction: str, num_call_ids: int = 1) -> str:
    """
    Identify the correlation use case based on SIP headers and direction.
    
    Uses dynamic rules loaded from YAML configuration files.
    Cases are evaluated in priority order (highest first).
    
    Args:
        call: The merged SipCall
        direction: "inbound" or "outbound"
        num_call_ids: Number of Call-IDs in the correlation group
        
    Returns:
        Use case identifier string (case name from matching YAML config)
    """
    loader = get_loader()
    cases = loader.get_cases()
    
    for case in cases:
        if _matches_case(call, direction, case, num_call_ids):
            LOGGER.debug(f"Matched correlation case: {case.name} (priority={case.priority})")
            return case.name
    
    # Fallback to unknown if no case matches
    LOGGER.warning(f"No correlation case matched for direction={direction}, using 'unknown'")
    return "unknown"


def _matches_case(call: SipCall, direction: str, case: CorrelationCase, num_call_ids: int = 1) -> bool:
    """
    Check if a call matches a correlation case's detection rules.
    
    Args:
        call: The SipCall to check
        direction: Call direction
        case: CorrelationCase with detection rules
        num_call_ids: Number of Call-IDs in the correlation group
        
    Returns:
        True if the call matches this case
    """
    detection = case.detection
    
    # Check direction
    if detection.direction != "both":
        if detection.direction != direction:
            return False
    
    # Check multi_call_id compatibility (NEW: protection against wrong use case)
    if case.correlation.multi_call_id is not None:
        has_multiple_call_ids = num_call_ids > 1
        
        if case.correlation.multi_call_id and not has_multiple_call_ids:
            # Use case expects multiple Call-IDs, but only 1 exists → reject
            LOGGER.debug(
                f"Skipping {case.name}: expects multi_call_id=true but only {num_call_ids} Call-ID(s) found"
            )
            return False
        
        if not case.correlation.multi_call_id and has_multiple_call_ids:
            # Use case expects single Call-ID, but multiple exist → reject
            LOGGER.debug(
                f"Skipping {case.name}: expects multi_call_id=false but {num_call_ids} Call-ID(s) found"
            )
            return False
    
    # Check method (if specified)
    if detection.method:
        method_found = False
        for msg in call.messages:
            if msg.is_request and (msg.method or "").upper() == detection.method.upper():
                method_found = True
                break
        if not method_found:
            return False
    
    # Check headers
    if detection.headers:
        headers_matched = []
        required_headers_matched = True
        
        for header_rule in detection.headers:
            rule_matched = False
            
            # Check all messages for this header
            for msg in call.messages:
                if msg.is_request and (not detection.method or 
                                       (msg.method or "").upper() == detection.method.upper()):
                    for header in msg.headers:
                        header_to_check = header.lower() if header_rule.case_insensitive else header
                        pattern_to_check = header_rule.pattern.lower() if header_rule.case_insensitive else header_rule.pattern
                        
                        if header_to_check.startswith(pattern_to_check):
                            rule_matched = True
                            break
                    
                    if rule_matched:
                        break
            
            headers_matched.append(rule_matched)
            
            # If this header is required and didn't match, fail immediately
            if header_rule.required and not rule_matched:
                required_headers_matched = False
                break
        
        # Must have at least one header match (if any headers defined)
        if not required_headers_matched or (headers_matched and not any(headers_matched)):
            return False
    
    return True


class GenericCorrelator(CorrelationStrategy):
    """
    Generic correlation strategy that implements the original/legacy correlation logic.
    
    This serves as the fallback correlator when no specific use case is detected.
    It handles both inbound and outbound calls using the embedded if/else logic.
    """
    
    def correlate(
        self,
        call: SipCall,
        direction: str,
        all_call_ids: List[str],
    ) -> CorrelationContext:
        """
        Build correlation context using the original/legacy logic.
        
        This is a direct copy of the original build_correlation_context() function.
        """
        # Delegate to the original function
        return build_correlation_context(call, direction, all_call_ids)


class InboundPSTNCarrierCorrelator(CorrelationStrategy):
    """
    Specialized correlation strategy for Inbound PSTN Carrier calls.
    
    Characteristics:
    - Carrier sends first INVITE with original media endpoints
    - Call flows: Carrier -> [RTP Engine] -> Core
    - Carrier media: from first INVITE and its 183/200 OK response
    - Core media: from last INVITE (to core) and its 183/200 OK response
    - May include Diversion or P-Asserted-Identity headers
    
    Future optimizations:
    - Skip RTP Engine detection if known carrier IPs are detected
    - Validate presence of expected PSTN headers
    - Apply carrier-specific SDP parsing rules
    - Handle carrier-specific media codec preferences
    """
    
    def correlate(
        self,
        call: SipCall,
        direction: str,
        all_call_ids: List[str],
    ) -> CorrelationContext:
        """
        Build correlation context for inbound PSTN carrier calls.
        
        Currently delegates to generic logic but with inbound-specific annotations.
        Future phases will implement optimizations specific to inbound PSTN scenarios.
        """
        # Force direction to inbound (sanity check)
        if direction != "inbound":
            LOGGER.warning(
                f"InboundPSTNCarrierCorrelator called with direction='{direction}', "
                f"forcing to 'inbound'"
            )
        
        # Delegate to generic logic
        ctx = build_correlation_context(call, "inbound", all_call_ids)
        
        # Add correlator-specific annotations
        ctx.log_lines.insert(0, "Correlator: InboundPSTNCarrierCorrelator")
        
        # Future: Add inbound-specific validations
        # - Validate Diversion/P-Asserted-Identity headers
        # - Check for expected carrier IP patterns
        # - Validate media codec negotiation
        
        return ctx


class OutboundPSTNCarrierCorrelator(CorrelationStrategy):
    """
    Specialized correlation strategy for Outbound PSTN Carrier calls.
    
    Characteristics:
    - Core sends first INVITE with media endpoints
    - Call flows: Core -> [RTP Engine] -> Carrier
    - Core media: from first INVITE and its 183/200 OK response
    - Carrier media: from last INVITE (to carrier) and its 183/200 OK response
    - Carrier discovery based on last hop destination IP
    
    Future optimizations:
    - Prioritize last hop media endpoints for carrier leg
    - Validate carrier response codes and timings
    - Handle asymmetric RTP scenarios (one-way audio detection)
    - Apply carrier-specific early media handling
    """
    
    def correlate(
        self,
        call: SipCall,
        direction: str,
        all_call_ids: List[str],
    ) -> CorrelationContext:
        """
        Build correlation context for outbound PSTN carrier calls.
        
        Currently delegates to generic logic but with outbound-specific annotations.
        Future phases will implement optimizations specific to outbound PSTN scenarios.
        """
        # Force direction to outbound (sanity check)
        if direction != "outbound":
            LOGGER.warning(
                f"OutboundPSTNCarrierCorrelator called with direction='{direction}', "
                f"forcing to 'outbound'"
            )
        
        # Delegate to generic logic
        ctx = build_correlation_context(call, "outbound", all_call_ids)
        
        # Add correlator-specific annotations
        ctx.log_lines.insert(0, "Correlator: OutboundPSTNCarrierCorrelator")
        
        # Future: Add outbound-specific validations
        # - Validate carrier response patterns
        # - Check for asymmetric media flows
        # - Validate carrier-side codec support
        
        return ctx


class DynamicCorrelator(CorrelationStrategy):
    """
    Dynamic correlation strategy that uses configuration from YAML files.
    
    This correlator reads its behavior from a CorrelationCase loaded from
    the correlation_cases directory.
    """
    
    def __init__(self, case: CorrelationCase):
        """
        Initialize with a correlation case configuration.
        
        Args:
            case: CorrelationCase loaded from YAML
        """
        self.case = case
    
    def correlate(
        self,
        call: SipCall,
        direction: str,
        all_call_ids: List[str],
    ) -> CorrelationContext:
        """
        Build correlation context using case configuration.
        
        Args:
            call: The SipCall
            direction: "inbound" or "outbound"
            all_call_ids: List of all Call-IDs
            
        Returns:
            CorrelationContext
        """
        # Use forced direction if specified
        actual_direction = self.case.correlation.force_direction or direction
        
        # Apply strategy (currently only 'generic' supported)
        if self.case.correlation.strategy == "generic":
            ctx = build_correlation_context(call, actual_direction, all_call_ids)
        else:
            LOGGER.warning(
                f"Unknown strategy '{self.case.correlation.strategy}' for case {self.case.name}, "
                f"using generic"
            )
            ctx = build_correlation_context(call, actual_direction, all_call_ids)
        
        # Add annotations from config
        for annotation in self.case.correlation.annotations:
            ctx.log_lines.insert(0, annotation)
        
        return ctx


def _extract_media_from_message(msg: SipMessage) -> Optional[MediaEndpoint]:
    """
    Extract media endpoint information from a SIP message (INVITE or response).
    
    Args:
        msg: SIP message with SDP
        
    Returns:
        MediaEndpoint or None if no media found
    """
    if not msg or not msg.has_sdp:
        return None
    
    rtp_ip = _extract_audio_connection_ip(msg)
    rtp_port = _extract_audio_port(msg)
    
    if not rtp_ip or not rtp_port:
        return None
    
    return MediaEndpoint(
        rtp_ip=rtp_ip,
        rtp_port=rtp_port,
        packet_number=msg.packet_number,
        method=msg.method if msg.is_request else f"{msg.status_code}OK",
    )


class ConfigurableCorrelator(CorrelationStrategy):
    """
    Configurable correlation strategy that uses YAML config for behavior.
    
    Supports TWO modes:
    1. NEW: Strategy from YAML file (modular architecture)
       - correlation.strategy: "direct_topology" or "rtp_engine_topology"
       - Loads strategy from rtphelper/correlation_strategies/
    
    2. LEGACY: Inline config (backward compatibility)
       - correlation.strategy: "configurable"
       - correlation.config: { ... inline config ... }
    
    Supports customizing:
    - IP extraction rules (carrier_ip_source, core_ip_source)
    - Response finding strategy (response_priority, fallback methods)
    - RTP Engine detection behavior
    - Special handling (filter_reinvites, group_multi_call_ids)
    """
    
    def __init__(self, case: 'CorrelationCase'):
        """
        Initialize with correlation case config.
        
        Tries to load strategy from YAML file first (new modular architecture),
        then falls back to inline config (legacy mode).
        """
        self.case = case
        self.config = case.correlation.config
        self.strategy_config: Optional['StrategyConfig'] = None
        
        # Try to load strategy from YAML file (new modular architecture)
        if MODULAR_ARCHITECTURE_AVAILABLE and case.correlation.strategy != "configurable":
            strategy_name = case.correlation.strategy
            try:
                self.strategy_config = get_strategy_config(strategy_name)
                if self.strategy_config:
                    LOGGER.info(f"✅ Loaded strategy '{strategy_name}' for case '{case.name}'")
                else:
                    LOGGER.warning(
                        f"Strategy '{strategy_name}' not found in YAML files, "
                        f"falling back to inline config for case '{case.name}'"
                    )
            except Exception as e:
                LOGGER.error(f"Failed to load strategy '{strategy_name}': {e}, using inline config")
                self.strategy_config = None
        
        # Fallback to inline config (legacy mode)
        if not self.strategy_config and not self.config:
            raise ValueError(f"ConfigurableCorrelator requires correlation.config or valid strategy for case {case.name}")
    
    def correlate(
        self,
        call: SipCall,
        direction: str,
        all_call_ids: List[str],
    ) -> CorrelationContext:
        """
        Build correlation context using configured rules.
        
        Args:
            call: The SipCall
            direction: "inbound" or "outbound"
            all_call_ids: List of all Call-IDs
            
        Returns:
            CorrelationContext with correlation results
        """
        # Use forced direction if specified
        actual_direction = self.case.correlation.force_direction or direction
        
        ctx = CorrelationContext(direction=actual_direction, call_ids=all_call_ids)
        
        # Add annotations
        for annotation in self.case.correlation.annotations:
            ctx.log_lines.append(annotation)
        
        # Multi Call-ID grouping (if enabled)
        # Check case config first (NEW), then inline config (LEGACY)
        multi_call_id_enabled = False
        if self.case.correlation.multi_call_id is not None:
            multi_call_id_enabled = self.case.correlation.multi_call_id
        elif self.config:
            multi_call_id_enabled = self.config.group_multi_call_ids
        
        if multi_call_id_enabled and len(all_call_ids) > 1:
            ctx.log_lines.append(f"INFO: Processing {len(all_call_ids)} related Call-IDs")
            ctx.log_lines.append("INFO: Multiple Call-IDs detected - assuming SBC is present in signaling path")
        
        # RTP Engine detection
        rtp_engine_enabled = False
        if self.strategy_config:
            rtp_engine_enabled = self.strategy_config.rtp_engine_detection.enabled
        elif self.config:
            rtp_engine_enabled = self.config.rtp_engine_detection == "enabled"
        
        if rtp_engine_enabled:
            ctx.rtp_engine = detect_rtp_engine(call, actual_direction)
            if ctx.rtp_engine.detected:
                ctx.log_lines.append(
                    f"INFO: RTP Engine SDP announcement detected - signaling node: {ctx.rtp_engine.xcc_ip}, "
                    f"RTP Engine public SDP IP: {ctx.rtp_engine.changed_sdp_ip}"
                )
        elif self.config and self.config.rtp_engine_detection == "optional":
            ctx.rtp_engine = detect_rtp_engine(call, actual_direction)
            # Don't fail if not detected
        # else: disabled - skip detection
        
        # Extract IPs using configured sources
        # NEW: Use strategy config if available
        selected_core_key = "core"
        if self.strategy_config:
            carrier_ip_source = self.strategy_config.get_ip_source("carrier", actual_direction)
            core_ip_source = self.strategy_config.get_ip_source("core", actual_direction)
            if not core_ip_source:
                # Some strategies (e.g. inbound_single_cid) model core-side endpoint as rtpengine.
                core_ip_source = self.strategy_config.get_ip_source("rtpengine", actual_direction)
                if core_ip_source:
                    selected_core_key = "rtpengine"
        else:
            # LEGACY: Use inline config
            carrier_ip_source = self.config.carrier_ip_source if self.config else None
            core_ip_source = self.config.core_ip_source if self.config else None
        
        carrier_ip = self._extract_ip(call, carrier_ip_source, actual_direction, ctx)
        core_ip = self._extract_ip(call, core_ip_source, actual_direction, ctx)

        # Strategy fallback support (e.g. source: target_host.resolved_ip with fallback: last_invite.dst_ip)
        if self.strategy_config:
            carrier_cfg = self.strategy_config.ip_extraction.get("carrier")
            core_cfg = self.strategy_config.ip_extraction.get(selected_core_key)

            if not carrier_ip and carrier_cfg and carrier_cfg.fallback_source:
                carrier_ip = self._extract_ip(call, carrier_cfg.fallback_source, actual_direction, ctx)
                if carrier_ip:
                    ctx.log_lines.append(f"INFO: Carrier IP extracted using fallback source: {carrier_cfg.fallback_source}")

            if not core_ip and core_cfg and core_cfg.fallback_source:
                core_ip = self._extract_ip(call, core_cfg.fallback_source, actual_direction, ctx)
                if core_ip:
                    ctx.log_lines.append(f"INFO: Core IP extracted using fallback source: {core_cfg.fallback_source}")
        
        if not carrier_ip or not core_ip:
            ctx.log_lines.append("ERROR: Failed to extract carrier or core IP")
            return ctx
        
        ctx.log_lines.append(f"INFO: Carrier IP: {carrier_ip}, Core IP: {core_ip}")
        
        # Build legs using configured response priority
        ctx.carrier_leg = self._build_leg(
            call, carrier_ip, actual_direction, "carrier", ctx
        )
        ctx.core_leg = self._build_leg(
            call, core_ip, actual_direction, "core", ctx
        )
        
        return ctx
    
    def _extract_ip(
        self,
        call: SipCall,
        source: Optional[str],
        direction: str,
        ctx: CorrelationContext,
    ) -> Optional[str]:
        """
        Extract IP based on configured source.
        
        Supported sources:
        - first_invite.src_ip
        - first_invite.dst_ip
        - last_invite.src_ip
        - last_invite.dst_ip
        - first_invite.via.received
        - last_invite.request_uri.host
        
        Args:
            call: SipCall
            source: Source string (e.g., "first_invite.src_ip")
            direction: Call direction
            ctx: CorrelationContext
            
        Returns:
            Extracted IP or None
        """
        if not source:
            return None
        
        parts = source.split('.')

        # Strategy placeholder for host-resolution outside SIP context.
        # In CLI/check scripts we don't have selected target host context here,
        # so caller should rely on configured fallback source.
        if parts[0] == "target_host" and len(parts) >= 2 and parts[1] == "resolved_ip":
            ctx.log_lines.append(
                "INFO: Source target_host.resolved_ip requires host context; using strategy fallback if configured"
            )
            return None
        
        # Get INVITE messages
        invites = [msg for msg in call.messages if msg.method == "INVITE"]
        
        if not invites:
            ctx.log_lines.append(f"WARN: No INVITE found for IP extraction source: {source}")
            return None
        
        # Sort by timestamp
        invites.sort(key=lambda m: m.ts)
        
        # Filter re-INVITEs if configured
        filter_reinvites = (
            self.strategy_config.reinvite_filtering.enabled
            if self.strategy_config
            else (self.config.filter_reinvites if self.config else True)
        )
        
        if filter_reinvites:
            initial_invites = [inv for inv in invites if not inv.to_tag]
            if initial_invites:
                invites = initial_invites
        
        # Select INVITE
        invite = None
        if parts[0] == "first_invite":
            invite = invites[0]
        elif parts[0] == "last_invite":
            invite = invites[-1]
        else:
            ctx.log_lines.append(f"WARN: Unknown invite selector: {parts[0]}")
            return None
        
        # Extract field from INVITE
        if len(parts) < 2:
            return None
        
        field = parts[1]
        
        if field == "src_ip":
            return invite.src_ip
        elif field == "dst_ip":
            return invite.dst_ip
        elif field == "via" and len(parts) >= 3:
            # first_invite.via.received
            subfield = parts[2]
            via_header = invite.headers.get("via", "")
            if subfield == "received" and "received=" in via_header.lower():
                # Parse received parameter from Via
                import re
                match = re.search(r'received=([0-9.]+)', via_header, re.IGNORECASE)
                if match:
                    return match.group(1)
        elif field == "request_uri" and len(parts) >= 3:
            # last_invite.request_uri.host
            subfield = parts[2]
            if subfield == "host":
                # Extract host from Request-URI
                import re
                req_uri = invite.request_uri or ""
                match = re.search(r'sip:([^@:;]+)', req_uri)
                if match:
                    return match.group(1)
        
        ctx.log_lines.append(f"WARN: Could not extract IP from source: {source}")
        return None
    
    def _build_leg(
        self,
        call: SipCall,
        ip: str,
        direction: str,
        leg_type: str,  # "carrier" or "core"
        ctx: CorrelationContext,
    ) -> Optional[LegInfo]:
        """
        Build leg information with configured response priority.
        
        Args:
            call: SipCall
            ip: IP address for this leg
            direction: Call direction
            leg_type: "carrier" or "core"
            ctx: CorrelationContext
            
        Returns:
            LegInfo or None
        """
        leg = LegInfo(leg_type=leg_type)
        
        # Find relevant INVITE for this leg
        invites = [msg for msg in call.messages if msg.method == "INVITE"]
        invites.sort(key=lambda m: m.ts)
        
        # Filter re-INVITEs if configured
        filter_reinvites = (
            self.strategy_config.reinvite_filtering.enabled
            if self.strategy_config
            else (self.config.filter_reinvites if self.config else True)
        )
        
        if filter_reinvites:
            initial_invites = [inv for inv in invites if not inv.to_tag]
            if initial_invites:
                invites = initial_invites
        
        # Select INVITE based on leg type
        invite = None
        if leg_type == "carrier":
            # For carrier, use first INVITE (inbound) or find INVITE to carrier (outbound)
            if direction == "inbound":
                invite = invites[0] if invites else None
            else:
                # Outbound: find INVITE going to carrier IP
                for inv in invites:
                    if inv.dst_ip == ip or inv.src_ip == ip:
                        invite = inv
                        break
                if not invite:
                    invite = invites[-1] if invites else None
        elif leg_type == "core":
            # For core, use last INVITE (inbound) or first INVITE (outbound)
            if direction == "inbound":
                invite = invites[-1] if invites else None
            else:
                invite = invites[0] if invites else None
        
        if not invite:
            ctx.log_lines.append(f"WARN: No INVITE found for {leg_type} leg")
            return None
        
        leg.invite = invite
        leg.source_ip = invite.src_ip
        leg.destination_ip = invite.dst_ip
        
        # Extract source media from INVITE
        leg.source_media = _extract_media_from_message(invite)
        
        # Find response using configured priority
        response = self._find_response_with_priority(call, invite, ctx)
        
        if response:
            if response.status_code == 183:
                leg.response_183 = response
            elif response.status_code == 200:
                leg.response_200 = response
            
            # Extract destination media from response
            leg.destination_media = _extract_media_from_message(response)
        else:
            ctx.log_lines.append(f"WARN: No response found for {leg_type} leg")
        
        return leg
    
    def _find_response_with_priority(
        self,
        call: SipCall,
        invite: SipMessage,
        ctx: CorrelationContext,
    ) -> Optional[SipMessage]:
        """
        Find response using configured priority order.
        
        Args:
            call: SipCall
            invite: INVITE message to find response for
            ctx: CorrelationContext
            
        Returns:
            SipMessage (response) or None
        """
        # Get response priority from strategy config or inline config
        if self.strategy_config:
            response_priority = self.strategy_config.response_finding.response_priority
        else:
            response_priority = self.config.response_priority if self.config else [183, 200]
        
        for status_code in response_priority:
            if status_code == 183:
                response = _find_183_progress_with_sdp_for_invite(call, invite)
                if response:
                    ctx.log_lines.append("INFO: Using 183 Session Progress response")
                    return response
            elif status_code == 200:
                response = _find_200ok_for_invite(call, invite)
                if response:
                    ctx.log_lines.append("INFO: Using 200 OK response")
                    return response
        
        # Fallback methods if configured
        enable_hop_fallback = (
            self.strategy_config.response_finding.enable_hop_fallback 
            if self.strategy_config 
            else (self.config.enable_hop_fallback if self.config else False)
        )
        enable_adjacent_packet_search = (
            self.strategy_config.response_finding.enable_adjacent_packet_search
            if self.strategy_config
            else (self.config.enable_adjacent_packet_search if self.config else False)
        )
        
        if enable_hop_fallback:
            ctx.log_lines.append("INFO: Attempting hop-based fallback for response")
            # This would need more complex logic - for now just log
        
        if enable_adjacent_packet_search:
            ctx.log_lines.append("INFO: Adjacent packet search enabled")
            # This would need more complex logic - for now just log
        
        return None


# Use case registry: maps use case name to correlator instance
USE_CASE_HANDLERS: Dict[str, CorrelationStrategy] = {
    "unknown": GenericCorrelator(),
    "inbound_pstn_carrier": InboundPSTNCarrierCorrelator(),
    "outbound_pstn_carrier": OutboundPSTNCarrierCorrelator(),
}


def _get_correlator_for_case(case_name: str) -> CorrelationStrategy:
    """
    Get correlator for a use case, creating dynamic correlator if needed.
    
    Args:
        case_name: Name of the correlation case
        
    Returns:
        CorrelationStrategy instance
    """
    # Check hardcoded handlers first (backward compatibility)
    if case_name in USE_CASE_HANDLERS:
        return USE_CASE_HANDLERS[case_name]
    
    # Load dynamic correlator from YAML config
    loader = get_loader()
    cases = loader.get_cases()
    
    for case in cases:
        if case.name == case_name:
            # Modular strategy cases (e.g. inbound_single_cid, direct_topology, rtp_engine_topology)
            # must use ConfigurableCorrelator so strategy YAML is loaded.
            if case.correlation.strategy not in {"generic", "configurable"}:
                return ConfigurableCorrelator(case)
            # Check if case has configurable correlation behavior
            if case.correlation.config and case.correlation.strategy == "configurable":
                return ConfigurableCorrelator(case)
            # Check if case uses generic strategy with config overrides
            elif case.correlation.config and case.correlation.strategy == "generic":
                # Could use ConfigurableCorrelator even for generic strategy if config is present
                # For now, use DynamicCorrelator which delegates to build_correlation_context
                return DynamicCorrelator(case)
            else:
                # Standard dynamic correlator
                return DynamicCorrelator(case)
    
    # Fallback to generic
    LOGGER.warning(f"No correlator found for case '{case_name}', using generic")
    return GenericCorrelator()


# ==============================================================================
# Helper Functions
# ==============================================================================
    

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


def _find_183_progress_with_sdp_for_invite(call: SipCall, invite: SipMessage) -> Optional[SipMessage]:
    """Find 183 Session Progress response with SDP for an INVITE."""
    candidates = [
        m for m in call.messages
        if (not m.is_request
            and m.status_code == 183
            and m.src_ip == invite.dst_ip
            and m.dst_ip == invite.src_ip
            and m.ts >= invite.ts
            and (m.ts - invite.ts) <= 180.0
            and m.has_sdp
            and _extract_audio_port(m) is not None)
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


def _find_response_for_invite_with_priority(call: SipCall, invite: SipMessage) -> Optional[SipMessage]:
    """
    Find SIP response for INVITE with priority: 183 Session Progress > 200 OK.
    Returns the first applicable response found.
    """
    # Priority 1: 183 Session Progress with SDP
    response_183 = _find_183_progress_with_sdp_for_invite(call, invite)
    if response_183:
        return response_183
    
    # Priority 2: 200 OK
    response_200 = _find_200ok_for_invite(call, invite)
    return response_200


def _find_response_to_hop(call: SipCall, hop_ip: str, after_ts: float, xcc_ip: Optional[str] = None) -> Optional[SipMessage]:
    """
    Find response (183 or 200) received by a specific hop IP.
    Used as fallback when primary response not found.
    
    This function finds INVITEs sent BY the hop (after it received and propagated
    the original INVITE), then finds responses to those propagated INVITEs.
    Those responses will be received by (dst_ip = hop_ip).
    
    Args:
        hop_ip: The IP that sends the propagated INVITE and receives its response
        after_ts: Only consider INVITEs sent after this timestamp
        xcc_ip: XCC/B2BUA server IP - if hop_ip equals this, fallback is blocked
    
    Returns:
        None if hop_ip equals xcc_ip (fallback blocked), otherwise the response message
    """
    # BLOCK FALLBACK if hop IP is the XCC IP
    # This prevents looking for responses at the XCC/B2BUA server
    if xcc_ip and hop_ip == xcc_ip:
        return None
    
    # Find INVITEs where this hop is the SOURCE (propagated INVITEs)
    invites = [
        m for m in call.messages
        if (m.is_request
            and (m.method or "").upper() == "INVITE"
            and m.src_ip == hop_ip  # Changed: look for INVITEs FROM hop
            and m.ts >= after_ts)
    ]
    invites.sort(key=lambda m: m.ts)
    
    # Try to find response for each INVITE
    for invite in invites:
        response = _find_response_for_invite_with_priority(call, invite)
        if response:
            return response
    
    return None


def _find_adjacent_response_with_sdp(call: SipCall, response: SipMessage) -> Optional[SipMessage]:
    """
    When a response lacks SDP info, check adjacent packets (same source host)
    for a response with same status code and valid SDP.
    
    Priority: previous packet first, then next packet.
    """
    if response.packet_number is None:
        return None
    
    by_packet = {m.packet_number: m for m in call.messages if m.packet_number is not None}
    
    # Check previous packet first
    prev_pkt = by_packet.get(response.packet_number - 1)
    if (prev_pkt
        and not prev_pkt.is_request
        and prev_pkt.status_code == response.status_code
        and prev_pkt.src_ip == response.src_ip
        and prev_pkt.has_sdp
        and _extract_audio_port(prev_pkt) is not None):
        return prev_pkt
    
    # Check next packet
    next_pkt = by_packet.get(response.packet_number + 1)
    if (next_pkt
        and not next_pkt.is_request
        and next_pkt.status_code == response.status_code
        and next_pkt.src_ip == response.src_ip
        and next_pkt.has_sdp
        and _extract_audio_port(next_pkt) is not None):
        return next_pkt
    
    return None


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
            engine_ip if (direction == "inbound" and engine_ip)
            else (last_invite.src_ip if direction == "outbound" else final_destination_ip)
        ),
    )
    
    # Get carrier media from first INVITE and its 200 OK/183
    if direction == "inbound":
        # For inbound, carrier media is from the first INVITE (carrier sends INVITE)
        carrier_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(first_invite) or "",
            rtp_port=_extract_audio_port(first_invite) or 0,
            packet_number=first_invite.packet_number,
            method="INVITE",
        )
        # Find 200 OK/183 going back to carrier.
        # If RTP engine is present, prefer the response of the INVITE entering engine.
        carrier_ok = None
        if engine_ip:
            invite_to_engine = _find_invite_to_engine(call, engine_ip, first_invite.ts)
            if invite_to_engine:
                carrier_ok = _find_response_for_invite_with_priority(call, invite_to_engine)
        if carrier_ok is None:
            carrier_ok = _find_response_for_invite_with_priority(call, first_invite)
        
        # Fallback: If still no response, look at first_invite_dst received responses
        if carrier_ok is None:
            first_hop = first_invite.dst_ip
            xcc_ip = ctx.rtp_engine.xcc_ip if ctx.rtp_engine.detected else None
            carrier_ok = _find_response_to_hop(call, first_hop, first_invite.ts, xcc_ip=xcc_ip)
            if carrier_ok:
                response_type = "183 Session Progress" if carrier_ok.status_code == 183 else "200 OK"
                ctx.log_lines.append(
                    f"INFO: Carrier {response_type} not found, using response to first hop "
                    f"(dst={first_hop}) packet={carrier_ok.packet_number}"
                )
            elif xcc_ip and first_hop == xcc_ip:
                ctx.log_lines.append(
                    f"WARN: Carrier 183/200 OK fallback blocked - first hop {first_hop} is XCC IP"
                )
        
        if carrier_ok:
            if not _extract_audio_port(carrier_ok):
                adj = _find_adjacent_response_with_sdp(call, carrier_ok)
                if adj:
                    carrier_ok = adj
            response_type = "183 Session Progress" if carrier_ok.status_code == 183 else "200 OK"
            carrier_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(carrier_ok) or "",
                rtp_port=_extract_audio_port(carrier_ok) or 0,
                packet_number=carrier_ok.packet_number,
                method=response_type,
            )
            carrier_leg.ok_200_packet = carrier_ok.packet_number
        carrier_leg.invite_packet = first_invite.packet_number
    else:
        # For outbound, carrier media is from the INVITE to carrier and its 200 OK/183
        # Find first INVITE to carrier (last hop)
        carrier_invite = last_invite
        carrier_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(carrier_invite) or "",
            rtp_port=_extract_audio_port(carrier_invite) or 0,
            packet_number=carrier_invite.packet_number,
            method="INVITE",
        )
        carrier_ok = _find_response_for_invite_with_priority(call, carrier_invite)
        
        # Fallback: If no response to last_invite (carrier), look at previous hop (last_invite.src_ip)
        if carrier_ok is None:
            previous_hop = carrier_invite.src_ip
            xcc_ip = ctx.rtp_engine.xcc_ip if ctx.rtp_engine.detected else None
            carrier_ok = _find_response_to_hop(call, previous_hop, first_invite.ts, xcc_ip=xcc_ip)
            if carrier_ok:
                response_type = "183 Session Progress" if carrier_ok.status_code == 183 else "200 OK"
                ctx.log_lines.append(
                    f"INFO: Carrier {response_type} not found, using response received by previous hop "
                    f"(ip={previous_hop}) packet={carrier_ok.packet_number}"
                )
            elif xcc_ip and previous_hop == xcc_ip:
                ctx.log_lines.append(
                    f"WARN: Carrier 183/200 OK fallback blocked - previous hop {previous_hop} is XCC IP"
                )
        
        if carrier_ok:
            if not _extract_audio_port(carrier_ok):
                adj = _find_adjacent_response_with_sdp(call, carrier_ok)
                if adj:
                    carrier_ok = adj
            response_type = "183 Session Progress" if carrier_ok.status_code == 183 else "200 OK"
            carrier_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(carrier_ok) or "",
                rtp_port=_extract_audio_port(carrier_ok) or 0,
                packet_number=carrier_ok.packet_number,
                method=response_type,
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
            core_ip if (direction == "inbound" and engine_ip)
            else (engine_ip if (direction == "outbound" and engine_ip) else source_ip)
        ),
    )
    
    if direction == "outbound":
        # For outbound, core media is from first INVITE (core sends) and its 200 OK/183
        core_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(first_invite) or "",
            rtp_port=_extract_audio_port(first_invite) or 0,
            packet_number=first_invite.packet_number,
            method="INVITE",
        )
        # Find 200 OK/183 for first_invite (from RTP Engine back to Core)
        core_ok = _find_response_for_invite_with_priority(call, first_invite)
        
        # Fallback: If no response to first_invite (core), look at next hop (first_invite.dst_ip)
        if core_ok is None:
            next_hop = first_invite.dst_ip
            xcc_ip = ctx.rtp_engine.xcc_ip if ctx.rtp_engine.detected else None
            core_ok = _find_response_to_hop(call, next_hop, first_invite.ts, xcc_ip=xcc_ip)
            if core_ok:
                response_type = "183 Session Progress" if core_ok.status_code == 183 else "200 OK"
                ctx.log_lines.append(
                    f"INFO: Core {response_type} not found directly, using response received by next hop "
                    f"(ip={next_hop}) packet={core_ok.packet_number}"
                )
            elif xcc_ip and next_hop == xcc_ip:
                ctx.log_lines.append(
                    f"WARN: Core 183/200 OK fallback blocked - next hop {next_hop} is XCC IP"
                )
        
        if core_ok and not _extract_audio_port(core_ok):
            adj_ok = _find_adjacent_response_with_sdp(call, core_ok)
            if adj_ok:
                core_ok = adj_ok
        if core_ok:
            response_type = "183 Session Progress" if core_ok.status_code == 183 else "200 OK"
            core_leg.destination_media = MediaEndpoint(
                rtp_ip=_extract_audio_connection_ip(core_ok) or "",
                rtp_port=_extract_audio_port(core_ok) or 0,
                packet_number=core_ok.packet_number,
                method=response_type,
            )
            core_leg.ok_200_packet = core_ok.packet_number
        core_leg.invite_packet = first_invite.packet_number
    else:
        # For inbound, core media is from the INVITE TO core (last hop) and its 200 OK/183
        core_invite = last_invite
        core_leg.source_media = MediaEndpoint(
            rtp_ip=_extract_audio_connection_ip(core_invite) or "",
            rtp_port=_extract_audio_port(core_invite) or 0,
            packet_number=core_invite.packet_number,
            method="INVITE",
        )
        
        # First try to find response using priority (183 > 200)
        core_ok = _find_response_for_invite_with_priority(call, core_invite)
        
        # Fallback: If no response to last_invite (core), look at previous hop (last_invite.src_ip)
        if core_ok is None:
            previous_hop = core_invite.src_ip
            xcc_ip = ctx.rtp_engine.xcc_ip if ctx.rtp_engine.detected else None
            core_ok = _find_response_to_hop(call, previous_hop, first_invite.ts, xcc_ip=xcc_ip)
            if core_ok:
                response_type = "183 Session Progress" if core_ok.status_code == 183 else "200 OK"
                ctx.log_lines.append(
                    f"INFO: Core {response_type} not found, using response received by previous hop "
                    f"(ip={previous_hop}) packet={core_ok.packet_number}"
                )
            elif xcc_ip and previous_hop == xcc_ip:
                ctx.log_lines.append(
                    f"WARN: Core 183/200 OK fallback blocked - previous hop {previous_hop} is XCC IP"
                )
        
        # If still no response, try the old ok_for_last as final fallback
        if core_ok is None:
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
            if ctx.direction == "outbound":
                ctx.log_lines.append("LEG: RTP ENGINE - CARRIER")
            else:
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


# ========================================
# TEMPLATE RENDERING ENGINE (Phase 3)
# ========================================

def render_filter_template(template: str, variables: Dict[str, Any]) -> str:
    """
    Render a filter template with variable substitution and conditionals.
    
    Supports:
    - Variable substitution: ${carrier.source.ip}
    - Conditionals: {% if direction == 'inbound' %}...{% endif %}
    - Conditionals with else: {% if direction == 'outbound' %}...{% else %}...{% endif %}
    
    Args:
        template: Template string with variables and conditionals
        variables: Dictionary of variables to substitute
        
    Returns:
        Rendered template string
    """
    import re
    
    if not template:
        return ""
    
    result = template
    
    # Process conditionals first ({% if ... %} ... {% endif %})
    # Pattern: {% if <condition> %}<content>{% endif %}
    # Pattern: {% if <condition> %}<content>{% else %}<other>{% endif %}
    
    def eval_condition(condition: str, vars: Dict[str, Any]) -> bool:
        """Evaluate a simple condition like 'direction == "inbound"'"""
        condition = condition.strip()
        
        # Handle == comparisons
        if "==" in condition:
            left, right = condition.split("==", 1)
            left = left.strip()
            right = right.strip().strip('"').strip("'")
            
            # Get variable value using dot notation
            left_value = vars
            for part in left.split('.'):
                if isinstance(left_value, dict):
                    left_value = left_value.get(part)
                else:
                    left_value = getattr(left_value, part, None)
                if left_value is None:
                    return False
            
            return str(left_value) == right
        
        # Handle != comparisons
        elif "!=" in condition:
            left, right = condition.split("!=", 1)
            left = left.strip()
            right = right.strip().strip('"').strip("'")
            
            left_value = vars
            for part in left.split('.'):
                if isinstance(left_value, dict):
                    left_value = left_value.get(part)
                else:
                    left_value = getattr(left_value, part, None)
                if left_value is None:
                    return True
            
            return str(left_value) != right
        
        # Handle simple boolean variables
        else:
            value = vars
            for part in condition.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = getattr(value, part, None)
                if value is None:
                    return False
            return bool(value)
    
    # Process conditionals with else
    conditional_else_pattern = re.compile(
        r'{%\s*if\s+([^%]+?)\s*%}(.*?){%\s*else\s*%}(.*?){%\s*endif\s*%}',
        re.DOTALL
    )
    
    def replace_conditional_else(match):
        condition = match.group(1)
        if_content = match.group(2)
        else_content = match.group(3)
        if eval_condition(condition, variables):
            return if_content
        else:
            return else_content
    
    result = conditional_else_pattern.sub(replace_conditional_else, result)
    
    # Process conditionals without else
    conditional_pattern = re.compile(
        r'{%\s*if\s+([^%]+?)\s*%}(.*?){%\s*endif\s*%}',
        re.DOTALL
    )
    
    def replace_conditional(match):
        condition = match.group(1)
        content = match.group(2)
        if eval_condition(condition, variables):
            return content
        else:
            return ""
    
    result = conditional_pattern.sub(replace_conditional, result)
    
    # Process variable substitutions (${var.path})
    variable_pattern = re.compile(r'\$\{([^}]+)\}')
    
    def replace_variable(match):
        var_path = match.group(1).strip()
        
        # Navigate through nested dict/object structure
        value = variables
        for part in var_path.split('.'):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = getattr(value, part, None)
            
            if value is None:
                LOGGER.warning(f"Variable {var_path} not found in template context")
                return f"${{{var_path}}}"  # Return original if not found
        
        return str(value)
    
    result = variable_pattern.sub(replace_variable, result)
    
    return result


def build_filter_variables(
    ctx: CorrelationContext,
    rtpengine_actual_ip: Optional[str] = None,
    for_count: bool = False
) -> Dict[str, Any]:
    """
    Build variable dictionary for filter template rendering.
    
    Creates a nested dictionary structure with all available filter variables:
    - carrier.source.ip, carrier.source.port
    - carrier.destination.ip, carrier.destination.port
    - core.source.ip, core.source.port
    - core.destination.ip, core.destination.port
    - rtpengine.detected, rtpengine.detected_ip, rtpengine.announced_ip
    - direction (inbound/outbound)
    - for_count (True for Phase 1, False for Phase 2)
    
    Args:
        ctx: Correlation context
        rtpengine_actual_ip: Actual RTP Engine IP detected from PCAP
        for_count: Whether this is Phase 1 (count) or Phase 2 (extract)
        
    Returns:
        Dictionary of template variables
    """
    public_rtpengine_ip = ctx.rtp_engine.changed_sdp_ip if ctx.rtp_engine else ""
    private_rtpengine_ip = rtpengine_actual_ip or ""
    variables = {
        "direction": ctx.direction,
        "for_count": for_count,
        "carrier": {},
        "core": {},
        "rtpengine": {
            "detected": ctx.rtp_engine.detected if ctx.rtp_engine else False,
            "detected_ip": private_rtpengine_ip,
            "announced_ip": public_rtpengine_ip,
            "public_ip": public_rtpengine_ip,
            "private_ip": private_rtpengine_ip,
            # Combined (Phase 1) uses public SDP IP, per-leg (Phase 2) uses private resolved IP.
            "resolved_ip": public_rtpengine_ip if for_count else (private_rtpengine_ip or public_rtpengine_ip),
        }
    }
    
    # Carrier leg variables
    if ctx.carrier_leg:
        leg = ctx.carrier_leg
        variables["carrier"] = {
            "source_ip": leg.source_ip or "",
            "destination_ip": leg.destination_ip or "",
            "source": {},
            "destination": {}
        }
        
        if leg.source_media:
            variables["carrier"]["source"] = {
                "ip": leg.source_media.rtp_ip or "",
                "port": leg.source_media.rtp_port or 0,
                "rtcp_port": getattr(leg.source_media, "rtcp_port", 0) or 0,
            }
        
        if leg.destination_media:
            variables["carrier"]["destination"] = {
                "ip": leg.destination_media.rtp_ip or "",
                "port": leg.destination_media.rtp_port or 0,
                "rtcp_port": getattr(leg.destination_media, "rtcp_port", 0) or 0,
            }
    
    # Core leg variables
    if ctx.core_leg:
        leg = ctx.core_leg
        variables["core"] = {
            "source_ip": leg.source_ip or "",
            "destination_ip": leg.destination_ip or "",
            "source": {},
            "destination": {}
        }
        
        if leg.source_media:
            variables["core"]["source"] = {
                "ip": leg.source_media.rtp_ip or "",
                "port": leg.source_media.rtp_port or 0,
                "rtcp_port": getattr(leg.source_media, "rtcp_port", 0) or 0,
            }
        
        if leg.destination_media:
            variables["core"]["destination"] = {
                "ip": leg.destination_media.rtp_ip or "",
                "port": leg.destination_media.rtp_port or 0,
                "rtcp_port": getattr(leg.destination_media, "rtcp_port", 0) or 0,
            }
    
    # Helper function for RTP Engine IP selection
    def get_rtpengine_ip_for_filter(sdp_ip: str) -> str:
        """Return RTP Engine IP based on phase: public SDP for combined, private resolved for per-leg."""
        if for_count:
            return sdp_ip
        if (rtpengine_actual_ip 
            and ctx.rtp_engine and ctx.rtp_engine.detected 
            and ctx.rtp_engine.changed_sdp_ip 
            and sdp_ip == ctx.rtp_engine.changed_sdp_ip):
            return rtpengine_actual_ip
        return sdp_ip
    
    # Add resolved RTP Engine IPs for each leg
    if ctx.carrier_leg and ctx.carrier_leg.destination_media:
        variables["carrier"]["rtpengine_ip"] = get_rtpengine_ip_for_filter(
            ctx.carrier_leg.destination_media.rtp_ip or ""
        )
    
    if ctx.core_leg and ctx.core_leg.destination_media:
        variables["core"]["rtpengine_ip"] = get_rtpengine_ip_for_filter(
            ctx.core_leg.destination_media.rtp_ip or ""
        )

    # RTP Engine port aliases for templates that model the RTP Engine as endpoint.
    # Canonical mapping: rtpengine.source.port == core.destination.port
    core_destination_port = None
    if isinstance(variables.get("core"), dict):
        core_destination = variables["core"].get("destination", {})
        if isinstance(core_destination, dict):
            core_destination_port = core_destination.get("port")

    core_source_port = None
    if isinstance(variables.get("core"), dict):
        core_source = variables["core"].get("source", {})
        if isinstance(core_source, dict):
            core_source_port = core_source.get("port")

    carrier_destination_port = None
    if isinstance(variables.get("carrier"), dict):
        carrier_destination = variables["carrier"].get("destination", {})
        if isinstance(carrier_destination, dict):
            carrier_destination_port = carrier_destination.get("port")

    carrier_source_port = None
    if isinstance(variables.get("carrier"), dict):
        carrier_source = variables["carrier"].get("source", {})
        if isinstance(carrier_source, dict):
            carrier_source_port = carrier_source.get("port")

    rtpengine_source_port = core_destination_port or core_source_port or carrier_destination_port or carrier_source_port or 0
    variables.setdefault("rtpengine", {})
    variables["rtpengine"]["source"] = {
        "port": rtpengine_source_port,
    }
    
    return variables


def get_builtin_template_set(template_set_name: str) -> List[Dict[str, Any]]:
    """
    Get built-in filter template set by name.
    
    Built-in template sets:
    - "rtp_engine_topology": 4-leg topology with RTP Engine (carrier <-> RTP Engine <-> core)
    - "direct_topology": 2-leg direct media topology (carrier <-> core)
    
    Args:
        template_set_name: Name of the template set
        
    Returns:
        List of filter step template dictionaries
    """
    templates = {
        "rtp_engine_topology": [
            {
                "step": 1,
                "leg_name": "carrier->host",
                "leg_key": "leg_carrier_rtpengine",
                "description": "RTP from carrier to RTP Engine",
                "phase1_template": """{% if direction == "outbound" %}ip.dst==${carrier.destination.ip} && udp.srcport==${carrier.source.port}{% else %}ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}{% endif %}""",
                "phase2_template": """{% if direction == "outbound" %}ip.src==${carrier.destination.ip} && udp.srcport==${carrier.destination.port}{% else %}ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}{% endif %}""",
                "required_fields": ["carrier.source.ip", "carrier.source.port"]
            },
            {
                "step": 2,
                "leg_name": "host->carrier",
                "leg_key": "leg_rtpengine_carrier",
                "description": "RTP from RTP Engine to carrier",
                "phase1_template": """{% if direction == "outbound" %}udp.srcport==${carrier.destination.port} && ip.src==${carrier.destination.ip}{% else %}udp.srcport==${carrier.destination.port} && ip.dst==${carrier.source.ip}{% endif %}""",
                "phase2_template": """{% if direction == "outbound" %}ip.src==${carrier.rtpengine_ip} && udp.srcport==${carrier.source.port}{% else %}ip.src==${carrier.rtpengine_ip} && udp.srcport==${carrier.destination.port}{% endif %}""",
                "required_fields": ["carrier.destination.port"]
            },
            {
                "step": 3,
                "leg_name": "host->core",
                "leg_key": "leg_rtpengine_core",
                "description": "RTP from RTP Engine to core",
                "phase1_template": """{% if direction == "outbound" %}udp.srcport==${core.source.port} && ip.src==${core.source.ip}{% else %}udp.srcport==${core.source.port} && ip.dst==${core.destination.ip}{% endif %}""",
                "phase2_template": """{% if direction == "outbound" %}ip.src==${core.rtpengine_ip} && udp.srcport==${core.destination.port}{% else %}ip.src==${core.rtpengine_ip} && udp.srcport==${core.source.port}{% endif %}""",
                "required_fields": ["core.source.port"]
            },
            {
                "step": 4,
                "leg_name": "core->host",
                "leg_key": "leg_core_rtpengine",
                "description": "RTP from core to RTP Engine",
                "phase1_template": """{% if direction == "outbound" %}ip.dst==${core.source.ip} && udp.srcport==${core.destination.port}{% else %}ip.src==${core.destination.ip} && udp.srcport==${core.destination.port}{% endif %}""",
                "phase2_template": """{% if direction == "outbound" %}ip.src==${core.source.ip} && udp.srcport==${core.source.port}{% else %}ip.src==${core.destination.ip} && udp.srcport==${core.destination.port}{% endif %}""",
                "required_fields": ["core.destination.ip", "core.destination.port"]
            }
        ],
        
        "direct_topology": [
            {
                "step": 1,
                "leg_name": "carrier->core",
                "leg_key": "leg_carrier_core",
                "description": "RTP from carrier to core (direct media)",
                "phase1_template": """ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}""",
                "phase2_template": """ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}""",
                "required_fields": ["carrier.source.ip", "carrier.source.port"]
            },
            {
                "step": 2,
                "leg_name": "core->carrier",
                "leg_key": "leg_core_carrier",
                "description": "RTP from core to carrier (direct media)",
                "phase1_template": """ip.src==${core.destination.ip} && udp.srcport==${core.destination.port}""",
                "phase2_template": """ip.src==${core.destination.ip} && udp.srcport==${core.destination.port}""",
                "required_fields": ["core.destination.ip", "core.destination.port"]
            }
        ],
        
        # Single Call-ID topology - RTP Engine as media termination
        # Uses resolved private IP of RTP Engine from hosts.yaml
        "inbound_single_cid": [
            {
                "step": 1,
                "leg_name": "carrier->rtpengine",
                "leg_key": "leg_carrier_rtpengine",
                "description": "RTP from carrier to RTP Engine",
                "phase1_template": """ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port} && ip.dst==${rtpengine.public_ip}""",
                "phase2_template": """ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port} && ip.dst==${rtpengine.resolved_ip}""",
                "required_fields": ["carrier.source.ip", "carrier.source.port", "rtpengine.resolved_ip"]
            },
            {
                "step": 2,
                "leg_name": "rtpengine->carrier",
                "leg_key": "leg_rtpengine_carrier",
                "description": "RTP from RTP Engine to carrier",
                "phase1_template": """ip.src==${rtpengine.public_ip} && ip.dst==${carrier.source.ip} && udp.dstport==${carrier.source.port}""",
                "phase2_template": """ip.src==${rtpengine.resolved_ip} && ip.dst==${carrier.source.ip} && udp.dstport==${carrier.source.port}""",
                "required_fields": ["carrier.source.ip", "carrier.source.port", "rtpengine.resolved_ip"]
            }
        ]
    }
    
    return templates.get(template_set_name, [])


def build_tshark_filters_from_template(
    ctx: CorrelationContext,
    template_set_name: str,
    rtpengine_actual_ip: Optional[str] = None,
    for_count: bool = False,
    custom_templates: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    Build tshark filters from template configuration.
    
    Uses template rendering engine to generate filter expressions from:
    - NEW: YAML filter templates (modular architecture)
    - LEGACY: Built-in template sets (rtp_engine_topology, direct_topology)
    - Custom templates from YAML config
    
    Args:
        ctx: Correlation context with leg information
        template_set_name: Name of template ("rtp_engine_4legs", "direct_2legs", etc)
        rtpengine_actual_ip: Actual RTP Engine IP detected from PCAP
        for_count: Whether this is Phase 1 (count) or Phase 2 (extract)
        custom_templates: Optional list of custom template dictionaries
        
    Returns:
        List of filter step dictionaries with rendered tshark_filter expressions
    """
    filters: List[Dict[str, Any]] = []
    
    # Build variable dictionary for template rendering
    variables = build_filter_variables(ctx, rtpengine_actual_ip, for_count)
    
    # Get templates (priority order: custom > YAML file > built-in)
    templates = None
    template_source = "unknown"
    
    # 1. Custom templates (highest priority)
    if custom_templates:
        templates = custom_templates
        template_source = "custom"
    
    # 2. Try to load from YAML file (new modular architecture)
    elif MODULAR_ARCHITECTURE_AVAILABLE:
        try:
            filter_template = get_filter_template(template_set_name)
            if filter_template:
                # Convert FilterStep objects to dict format
                templates = []
                for step in filter_template.steps:
                    templates.append({
                        "step": step.step,
                        "leg_name": step.leg_name,
                        "leg_key": step.leg_key,
                        "description": step.description,
                        "phase1_template": step.phase1_template,
                        "phase2_template": step.phase2_template,
                        "required_fields": step.required_fields
                    })
                template_source = f"YAML file ({filter_template.file_path.name})"
                LOGGER.info(f"✅ Using filter template '{template_set_name}' from {template_source}")
        except Exception as e:
            LOGGER.warning(f"Failed to load filter template '{template_set_name}' from YAML: {e}")
    
    # 3. Fallback to built-in templates (legacy)
    if not templates:
        templates = get_builtin_template_set(template_set_name)
        if templates:
            template_source = "built-in"
            LOGGER.info(f"Using built-in template set '{template_set_name}'")
    
    if not templates:
        LOGGER.warning(f"No templates found for template set: {template_set_name}")
        return filters
    
    # Render each template step
    for template in templates:
        step = template.get("step", 0)
        leg_name = template.get("leg_name", "")
        leg_key = template.get("leg_key", "")
        description = template.get("description", "")
        required_fields = template.get("required_fields", [])
        
        # Select template based on phase
        template_str = template.get("phase2_template", "") if not for_count else template.get("phase1_template", "")
        
        # Check if required fields are available
        missing_fields = []
        for field_path in required_fields:
            value = variables
            for part in field_path.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = getattr(value, part, None)
                if value is None or value == "" or value == 0:
                    missing_fields.append(field_path)
                    break
        
        # Render template if all required fields available
        if not missing_fields and template_str:
            try:
                rendered_filter = render_filter_template(template_str, variables)
                filters.append({
                    "step": step,
                    "leg": leg_name,
                    "leg_key": leg_key,
                    "available": True,
                    "tshark_filter": rendered_filter,
                    "reason": None,
                    "description": description
                })
            except Exception as e:
                LOGGER.error(f"Error rendering template for step {step}: {e}")
                filters.append({
                    "step": step,
                    "leg": leg_name,
                    "leg_key": leg_key,
                    "available": False,
                    "tshark_filter": None,
                    "reason": f"template render error: {str(e)}",
                    "description": description
                })
        else:
            # Filter unavailable due to missing fields
            reason = f"missing fields: {', '.join(missing_fields)}" if missing_fields else "no template defined"
            filters.append({
                "step": step,
                "leg": leg_name,
                "leg_key": leg_key,
                "available": False,
                "tshark_filter": None,
                "reason": reason,
                "description": description
            })
    
    return filters


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

    # Prefer use-case template filters to keep leg count aligned with selected case.
    template_name = (getattr(ctx, "filter_template_name", None) or "").strip()
    if template_name:
        template_filters = build_tshark_filters_from_template(
            ctx=ctx,
            template_set_name=template_name,
            rtpengine_actual_ip=rtpengine_actual_ip,
            for_count=for_count,
        )
        if template_filters:
            expected_legs = getattr(ctx, "expected_legs", None)
            if isinstance(expected_legs, int) and expected_legs > 0:
                template_filters = sorted(template_filters, key=lambda item: int(item.get("step") or 0))[:expected_legs]
            return template_filters
    
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
            # For OUTBOUND Phase 2: Carrier sends FROM carrier reply address (200 OK)
            if ctx.direction == "outbound" and carrier.destination_media.rtp_ip and not for_count:
                filter_expr = f"ip.src=={carrier.destination_media.rtp_ip} && udp.srcport=={carrier.destination_media.rtp_port}"
            elif ctx.direction == "outbound" and carrier.destination_media.rtp_ip:
                # OUTBOUND Phase 1: Use destination IP for counting
                filter_expr = f"ip.dst=={carrier.destination_media.rtp_ip} && udp.srcport=={carrier.source_media.rtp_port}"
            else:
                # INBOUND: Source is carrier IP and port from INVITE
                filter_expr = f"ip.src=={carrier.source_media.rtp_ip} && udp.srcport=={carrier.source_media.rtp_port}"
            
            filters.append({
                "step": 1,
                "leg": "carrier->host",
                "leg_key": "leg_carrier_rtpengine",
                "available": True,
                "tshark_filter": filter_expr,
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
                # Phase 1 count
                if ctx.direction == "outbound":
                    # OUTBOUND: Carrier sends back FROM carrier IP (known)
                    filter_expr = f"udp.srcport=={carrier.destination_media.rtp_port} && ip.src=={carrier.destination_media.rtp_ip}"
                else:
                    # INBOUND: don't filter by RTP Engine IP (not yet detected)
                    filter_expr = f"udp.srcport=={carrier.destination_media.rtp_port} && ip.dst=={carrier.source_media.rtp_ip}"
            else:
                # Phase 2 extract
                if ctx.direction == "outbound":
                    # OUTBOUND: RTP Engine IP is in carrier.source_media (announced in INVITE to carrier)
                    rtpengine_ip = get_rtpengine_ip_for_filter(carrier.source_media.rtp_ip)
                    filter_expr = f"ip.src=={rtpengine_ip} && udp.srcport=={carrier.source_media.rtp_port}"
                else:
                    # INBOUND: use actual RTP Engine IP, omit destination IP
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
                # Phase 1 count
                if ctx.direction == "outbound":
                    # OUTBOUND: Core sends FROM core IP (known)
                    filter_expr = f"udp.srcport=={core.source_media.rtp_port} && ip.src=={core.source_media.rtp_ip}"
                else:
                    # INBOUND: don't filter by RTP Engine IP (not yet detected)
                    filter_expr = f"udp.srcport=={core.source_media.rtp_port} && ip.dst=={core.destination_media.rtp_ip}"
            else:
                # Phase 2 extract
                if ctx.direction == "outbound":
                    # OUTBOUND: RTP Engine IP is in core.destination_media (announced in 200 OK to core)
                    rtpengine_ip = get_rtpengine_ip_for_filter(core.destination_media.rtp_ip)
                    filter_expr = f"ip.src=={rtpengine_ip} && udp.srcport=={core.destination_media.rtp_port}"
                else:
                    # INBOUND: RTP Engine IP is in core.destination_media (announced in 200 OK from core)
                    # core.source_media contains carrier IP (unchanged INVITE), NOT RTP Engine IP
                    rtpengine_ip = get_rtpengine_ip_for_filter(core.destination_media.rtp_ip)
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
            # For OUTBOUND Phase 2: Core sends FROM core original address (INVITE)
            if ctx.direction == "outbound" and core.source_media.rtp_ip and not for_count:
                filter_expr = f"ip.src=={core.source_media.rtp_ip} && udp.srcport=={core.source_media.rtp_port}"
            elif ctx.direction == "outbound" and core.source_media.rtp_ip:
                # OUTBOUND Phase 1: Use destination IP for counting
                filter_expr = f"ip.dst=={core.source_media.rtp_ip} && udp.srcport=={core.destination_media.rtp_port}"
            else:
                # INBOUND: Core's IP and port from 200 OK
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
    
    expected_legs = getattr(ctx, "expected_legs", None)
    if isinstance(expected_legs, int) and expected_legs > 0:
        filters = sorted(filters, key=lambda item: int(item.get("step") or 0))[:expected_legs]

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
    use_case: Optional[str] = None,
) -> Tuple[CorrelationContext, SipCall]:
    """
    Main entry point for SIP correlation.
    
    Args:
        parse_result: Parsed SIP pcap result
        direction: "inbound" or "outbound"
        primary_call_id: Optional specific Call-ID to focus on
        use_case: Optional use case identifier (auto-detected if None)
        
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
    
    # Identify use case if not provided
    if use_case is None:
        use_case = identify_use_case(merged_call, direction, num_call_ids=len(target_group))
        LOGGER.debug(f"Auto-detected use case: {use_case}")
    
    # Get appropriate correlation strategy (dynamic or hardcoded)
    handler = _get_correlator_for_case(use_case)
    
    # Build correlation context using strategy
    all_call_ids = sorted(target_group)
    ctx = handler.correlate(merged_call, direction, all_call_ids)

    # Attach selected case metadata so filter builder respects per-use-case leg count.
    ctx.use_case = use_case
    selected_case = None
    try:
        selected_case = next((c for c in get_loader().get_cases() if c.name == use_case), None)
        if selected_case and selected_case.filters and selected_case.filters.template_set:
            ctx.filter_template_name = selected_case.filters.template_set
            if MODULAR_ARCHITECTURE_AVAILABLE:
                filter_template = get_filter_template(selected_case.filters.template_set)
            else:
                filter_template = None
            if filter_template:
                ctx.expected_legs = int(filter_template.legs)
            else:
                builtin_steps = get_builtin_template_set(selected_case.filters.template_set)
                if builtin_steps:
                    ctx.expected_legs = len(builtin_steps)
    except Exception as exc:
        LOGGER.debug(
            "Failed to resolve template metadata for use_case=%s: %s",
            use_case,
            exc,
            extra={"category": "SIP_CORRELATION"},
        )

    # Add use case, strategy and filter template to context for debugging.
    # insert(0, ...) in reverse desired order so final list reads top-to-bottom:
    #   Use Case: ...  →  Correlation Strategy: ...  →  Filter Template: ...
    if selected_case:
        template_name = (selected_case.filters.template_set if selected_case.filters else None) or "none"
        strategy_name = selected_case.correlation.strategy or "none"
        ctx.log_lines.insert(0, f"Filter Template: {template_name}")
        ctx.log_lines.insert(0, f"Correlation Strategy: {strategy_name}")
    ctx.log_lines.insert(0, f"Use Case: {use_case}")
    
    return ctx, merged_call
