#!/usr/bin/env python3
"""
Phase 2 Demonstration: Specific Correlation Strategies

This script demonstrates the new correlation strategies implemented in Phase 2.
"""

import sys
from dataclasses import dataclass, field
from typing import List, Optional


# Mock classes for demonstration (matches test structure)
@dataclass
class MockMediaSection:
    media_type: str = "audio"
    port: int = 5060
    protocol: str = "RTP/AVP"
    connection_ip: Optional[str] = None
    sdes_cryptos: List = field(default_factory=list)


@dataclass
class MockSipMessage:
    packet_number: int
    ts: float
    src_ip: str
    dst_ip: str
    proto: str = "udp"
    is_request: bool = True
    method: Optional[str] = None
    status_code: Optional[int] = None
    call_id: Optional[str] = None
    has_sdp: bool = False
    media_sections: List[MockMediaSection] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    cseq_method: Optional[str] = None
    via_branch: Optional[str] = None
    to_tag: Optional[str] = None
    from_tag: Optional[str] = None
    other_leg_call_id: Optional[str] = None


@dataclass
class MockSipCall:
    call_id: str
    messages: List[MockSipMessage] = field(default_factory=list)
    media_sections: List[MockMediaSection] = field(default_factory=list)


def demo_inbound_correlation():
    """Demonstrate InboundPSTNCarrierCorrelator."""
    print("=" * 70)
    print("DEMO: InboundPSTNCarrierCorrelator")
    print("=" * 70)
    
    from rtphelper.services.sip_correlation import InboundPSTNCarrierCorrelator
    
    correlator = InboundPSTNCarrierCorrelator()
    
    # Create mock inbound call with Diversion header
    call = MockSipCall(call_id="inbound-123")
    call.messages = [
        MockSipMessage(
            packet_number=1,
            ts=1.0,
            src_ip="203.0.113.10",  # Carrier IP
            dst_ip="10.20.30.40",    # Core IP
            is_request=True,
            method="INVITE",
            call_id="inbound-123",
            has_sdp=True,
            headers=["Diversion: <sip:+15551234567@carrier.example.com>"],
            media_sections=[MockMediaSection(connection_ip="203.0.113.10", port=10000)],
        ),
        MockSipMessage(
            packet_number=2,
            ts=1.5,
            src_ip="10.20.30.40",   # Core IP
            dst_ip="203.0.113.10",  # Carrier IP
            is_request=False,
            status_code=200,
            cseq_method="INVITE",
            call_id="inbound-123",
            has_sdp=True,
            media_sections=[MockMediaSection(connection_ip="10.20.30.40", port=20000)],
        ),
    ]
    
    print("\nCall Flow: Carrier (203.0.113.10) -> Core (10.20.30.40)")
    print("Headers: Diversion header present (typical PSTN inbound)")
    
    ctx = correlator.correlate(call, "inbound", ["inbound-123"])
    
    print(f"\n✓ Correlation completed")
    print(f"  Direction: {ctx.direction}")
    print(f"  Call-IDs: {ctx.call_ids}")
    print(f"  Correlator Used: {ctx.log_lines[0]}")
    print(f"\n  Carrier Leg:")
    print(f"    Source IP: {ctx.carrier_leg.source_ip if ctx.carrier_leg else 'N/A'}")
    print(f"    Dest IP:   {ctx.carrier_leg.destination_ip if ctx.carrier_leg else 'N/A'}")
    print(f"\n  Core Leg:")
    print(f"    Source IP: {ctx.core_leg.source_ip if ctx.core_leg else 'N/A'}")
    print(f"    Dest IP:   {ctx.core_leg.destination_ip if ctx.core_leg else 'N/A'}")
    
    return ctx


def demo_outbound_correlation():
    """Demonstrate OutboundPSTNCarrierCorrelator."""
    print("\n" + "=" * 70)
    print("DEMO: OutboundPSTNCarrierCorrelator")
    print("=" * 70)
    
    from rtphelper.services.sip_correlation import OutboundPSTNCarrierCorrelator
    
    correlator = OutboundPSTNCarrierCorrelator()
    
    # Create mock outbound call
    call = MockSipCall(call_id="outbound-456")
    call.messages = [
        MockSipMessage(
            packet_number=1,
            ts=1.0,
            src_ip="10.20.30.40",    # Core IP
            dst_ip="203.0.113.20",   # Carrier IP
            is_request=True,
            method="INVITE",
            call_id="outbound-456",
            has_sdp=True,
            media_sections=[MockMediaSection(connection_ip="10.20.30.40", port=30000)],
        ),
        MockSipMessage(
            packet_number=2,
            ts=1.5,
            src_ip="203.0.113.20",  # Carrier IP
            dst_ip="10.20.30.40",   # Core IP
            is_request=False,
            status_code=200,
            cseq_method="INVITE",
            call_id="outbound-456",
            has_sdp=True,
            media_sections=[MockMediaSection(connection_ip="203.0.113.20", port=40000)],
        ),
    ]
    
    print("\nCall Flow: Core (10.20.30.40) -> Carrier (203.0.113.20)")
    print("Headers: Standard outbound call")
    
    ctx = correlator.correlate(call, "outbound", ["outbound-456"])
    
    print(f"\n✓ Correlation completed")
    print(f"  Direction: {ctx.direction}")
    print(f"  Call-IDs: {ctx.call_ids}")
    print(f"  Correlator Used: {ctx.log_lines[0]}")
    print(f"\n  Core Leg:")
    print(f"    Source IP: {ctx.core_leg.source_ip if ctx.core_leg else 'N/A'}")
    print(f"    Dest IP:   {ctx.core_leg.destination_ip if ctx.core_leg else 'N/A'}")
    print(f"\n  Carrier Leg:")
    print(f"    Source IP: {ctx.carrier_leg.source_ip if ctx.carrier_leg else 'N/A'}")
    print(f"    Dest IP:   {ctx.carrier_leg.destination_ip if ctx.carrier_leg else 'N/A'}")
    
    return ctx


def demo_use_case_detection():
    """Demonstrate automatic use case detection."""
    print("\n" + "=" * 70)
    print("DEMO: Automatic Use Case Detection")
    print("=" * 70)
    
    from rtphelper.services.sip_correlation import identify_use_case
    
    # Case 1: Inbound with Diversion header
    call1 = MockSipCall(call_id="test-1")
    call1.messages = [
        MockSipMessage(
            packet_number=1, ts=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            is_request=True, method="INVITE",
            headers=["Diversion: <sip:+15551234567@example.com>"]
        )
    ]
    use_case1 = identify_use_case(call1, "inbound")
    print(f"\n✓ Call with Diversion header + inbound direction")
    print(f"  Detected use case: {use_case1}")
    
    # Case 2: Inbound with P-Asserted-Identity
    call2 = MockSipCall(call_id="test-2")
    call2.messages = [
        MockSipMessage(
            packet_number=1, ts=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            is_request=True, method="INVITE",
            headers=["P-Asserted-Identity: <sip:+15559876543@example.com>"]
        )
    ]
    use_case2 = identify_use_case(call2, "inbound")
    print(f"\n✓ Call with P-Asserted-Identity + inbound direction")
    print(f"  Detected use case: {use_case2}")
    
    # Case 3: Outbound without special headers
    call3 = MockSipCall(call_id="test-3")
    call3.messages = [
        MockSipMessage(
            packet_number=1, ts=1.0, src_ip="2.2.2.2", dst_ip="1.1.1.1",
            is_request=True, method="INVITE",
            headers=[]
        )
    ]
    use_case3 = identify_use_case(call3, "outbound")
    print(f"\n✓ Call without special headers + outbound direction")
    print(f"  Detected use case: {use_case3}")


def demo_registry():
    """Demonstrate USE_CASE_HANDLERS registry."""
    print("\n" + "=" * 70)
    print("DEMO: USE_CASE_HANDLERS Registry")
    print("=" * 70)
    
    from rtphelper.services.sip_correlation import (
        USE_CASE_HANDLERS,
        GenericCorrelator,
        InboundPSTNCarrierCorrelator,
        OutboundPSTNCarrierCorrelator,
    )
    
    print(f"\nRegistered handlers: {len(USE_CASE_HANDLERS)}")
    for use_case, handler in USE_CASE_HANDLERS.items():
        handler_class = handler.__class__.__name__
        print(f"  '{use_case}' -> {handler_class}")
    
    # Verify types
    print("\n✓ Handler type verification:")
    print(f"  'unknown' is GenericCorrelator: {isinstance(USE_CASE_HANDLERS['unknown'], GenericCorrelator)}")
    print(f"  'inbound_pstn_carrier' is InboundPSTNCarrierCorrelator: {isinstance(USE_CASE_HANDLERS['inbound_pstn_carrier'], InboundPSTNCarrierCorrelator)}")
    print(f"  'outbound_pstn_carrier' is OutboundPSTNCarrierCorrelator: {isinstance(USE_CASE_HANDLERS['outbound_pstn_carrier'], OutboundPSTNCarrierCorrelator)}")


def main():
    """Run all demonstrations."""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "PHASE 2: SPECIFIC CORRELATORS DEMO" + " " * 19 + "║")
    print("╚" + "═" * 68 + "╝")
    
    try:
        # Demo 1: Registry
        demo_registry()
        
        # Demo 2: Use case detection
        demo_use_case_detection()
        
        # Demo 3: Inbound correlation
        demo_inbound_correlation()
        
        # Demo 4: Outbound correlation
        demo_outbound_correlation()
        
        print("\n" + "=" * 70)
        print("✅ All demonstrations completed successfully!")
        print("=" * 70)
        print("\nPhase 2 Features:")
        print("  ✓ InboundPSTNCarrierCorrelator - Specialized for inbound PSTN")
        print("  ✓ OutboundPSTNCarrierCorrelator - Specialized for outbound PSTN")
        print("  ✓ Automatic use case detection via headers")
        print("  ✓ Registry-based handler selection")
        print("  ✓ Backward compatible with Phase 1")
        print("=" * 70)
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
