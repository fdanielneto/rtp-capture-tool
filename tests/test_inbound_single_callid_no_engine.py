#!/usr/bin/env python3
"""
Practical Example: Test for "Inbound 1 Call-ID Without RTP Engine" Scenario

This file can be copied directly to tests/test_sip_correlation.py
or executed standalone to validate the scenario.
"""
from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

# Permitir importação do módulo rtphelper
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# Mock classes (copiar das linhas 10-46 de tests/test_sip_correlation.py)
@dataclass
class MockMediaSection:
    media_type: str = "audio"
    port: int = 5060
    protocol: str = "RTP/AVP"
    connection_ip: Optional[str] = None
    sdes_cryptos: List = field(default_factory=list)


@dataclass
class MockSipMessage:
    packet_number: Optional[int]
    ts: float
    src_ip: str
    dst_ip: str
    proto: str = "udp"
    is_request: bool = True
    method: Optional[str] = None
    status_code: Optional[int] = None
    cseq_num: Optional[int] = None
    cseq_method: Optional[str] = None
    via_branch: Optional[str] = None
    to_tag: Optional[str] = None
    from_tag: Optional[str] = None
    call_id: Optional[str] = None
    other_leg_call_id: Optional[str] = None
    has_sdp: bool = False
    media_sections: List[MockMediaSection] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)


@dataclass
class MockSipCall:
    call_id: str
    media_sections: List[MockMediaSection] = field(default_factory=list)
    transport_tuples: Set[Tuple[str, int, str, int, str]] = field(default_factory=set)
    messages: List[MockSipMessage] = field(default_factory=list)


class TestInboundSingleCallIDNoEngine(unittest.TestCase):
    """
    Tests for specific scenario: Inbound with 1 Call-ID without RTP Engine.
    
    Scenario characteristics:
    - Only 1 Call-ID (no B2BUA multi-leg)
    - Direction: inbound (Carrier → Core)
    - No SDP Changes: same c= line in INVITE and 200 OK (no RTP Engine)
    - Direct path: Carrier sends INVITE directly to Core
    """

    def test_inbound_single_callid_no_rtp_engine(self):
        """
        Test inbound call with:
        - Single Call-ID
        - No RTP Engine (no SDP c= changes)
        - Direct carrier-to-core path
        
        Call Flow:
        1. Carrier (203.0.113.50) → INVITE → Core (10.20.30.100)
           - SDP: c=IN IP4 203.0.113.50, m=audio 20000
        2. Core (10.20.30.100) → 200 OK → Carrier (203.0.113.50)
           - SDP: c=IN IP4 10.20.30.100, m=audio 30000
        
        Expected:
        - ctx.direction == "inbound"
        - ctx.call_ids == ["single-inbound-123"]
        - ctx.rtp_engine.detected == False (no SDP changes)
        - Carrier leg: source=203.0.113.50, dest=10.20.30.100
        - Core leg: same IPs (no RTP Engine in between)
        """
        from rtphelper.services.sip_correlation import build_correlation_context
        
        call = MockSipCall(call_id="single-inbound-123")
        
        # Scenario: Carrier sends INVITE directly to Core (no RTP Engine)
        call.messages = [
            # INVITE do Carrier para Core
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="203.0.113.50",      # Carrier IP (público)
                dst_ip="10.20.30.100",       # Core IP (privado)
                is_request=True,
                method="INVITE",
                call_id="single-inbound-123",
                has_sdp=True,
                headers=["Diversion: <sip:+15551234567@carrier.example.com>"],
                media_sections=[
                    MockMediaSection(
                        connection_ip="203.0.113.50",  # Carrier RTP IP (mesmo que signaling)
                        port=20000,                     # Carrier RTP port
                    )
                ],
            ),
            # 200 OK do Core para Carrier
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="10.20.30.100",      # Core IP
                dst_ip="203.0.113.50",      # Carrier IP
                is_request=False,
                status_code=200,
                cseq_method="INVITE",
                call_id="single-inbound-123",
                has_sdp=True,
                media_sections=[
                    MockMediaSection(
                        connection_ip="10.20.30.100",  # Core RTP IP (mesmo que signaling)
                        port=30000,                     # Core RTP port
                    )
                ],
            ),
        ]
        
        # Execute correlation
        ctx = build_correlation_context(call, "inbound", ["single-inbound-123"])
        
        # ============================================================
        # VALIDATIONS
        # ============================================================
        
        # 1. Direction
        self.assertEqual(ctx.direction, "inbound", "Direction should be 'inbound'")
        
        # 2. Call IDs (apenas 1)
        self.assertEqual(len(ctx.call_ids), 1, "Should have exactly 1 Call-ID")
        self.assertIn("single-inbound-123", ctx.call_ids, "Call-ID should match")
        
        # 3. RTP Engine NOT detected (no SDP c= changes)
        self.assertFalse(
            ctx.rtp_engine.detected,
            "RTP Engine should NOT be detected (no SDP c= changes)"
        )
        
        # 4. Carrier Leg - IPs
        self.assertIsNotNone(ctx.carrier_leg, "Carrier leg should exist")
        self.assertEqual(
            ctx.carrier_leg.source_ip,
            "203.0.113.50",
            "Carrier source IP should be carrier public IP"
        )
        self.assertEqual(
            ctx.carrier_leg.destination_ip,
            "10.20.30.100",
            "Carrier destination IP should be core IP"
        )
        
        # 5. Carrier Leg - Media Endpoints
        self.assertIsNotNone(ctx.carrier_leg.source_media, "Carrier source media should exist")
        self.assertEqual(
            ctx.carrier_leg.source_media.rtp_ip,
            "203.0.113.50",
            "Carrier source media IP should match INVITE SDP c="
        )
        self.assertEqual(
            ctx.carrier_leg.source_media.rtp_port,
            20000,
            "Carrier source media port should match INVITE SDP m=audio"
        )
        
        self.assertIsNotNone(ctx.carrier_leg.destination_media, "Carrier destination media should exist")
        self.assertEqual(
            ctx.carrier_leg.destination_media.rtp_ip,
            "10.20.30.100",
            "Carrier destination media IP should match 200 OK SDP c="
        )
        self.assertEqual(
            ctx.carrier_leg.destination_media.rtp_port,
            30000,
            "Carrier destination media port should match 200 OK SDP m=audio"
        )
        
        # 6. Core Leg - IPs
        self.assertIsNotNone(ctx.core_leg, "Core leg should exist")
        # In scenarios without RTP Engine, core_leg has the same IPs
        self.assertEqual(
            ctx.core_leg.source_ip,
            "203.0.113.50",
            "Core source IP should be carrier IP (no RTP Engine)"
        )
        self.assertEqual(
            ctx.core_leg.destination_ip,
            "10.20.30.100",
            "Core destination IP should be core IP"
        )
        
        # 7. Core Leg - Media Endpoints
        self.assertIsNotNone(ctx.core_leg.source_media, "Core source media should exist")
        self.assertEqual(
            ctx.core_leg.source_media.rtp_ip,
            "203.0.113.50",
            "Core source media IP should match INVITE SDP c="
        )
        self.assertEqual(
            ctx.core_leg.source_media.rtp_port,
            20000,
            "Core source media port should match INVITE SDP m=audio"
        )
        
        self.assertIsNotNone(ctx.core_leg.destination_media, "Core destination media should exist")
        self.assertEqual(
            ctx.core_leg.destination_media.rtp_ip,
            "10.20.30.100",
            "Core destination media IP should match 200 OK SDP c="
        )
        self.assertEqual(
            ctx.core_leg.destination_media.rtp_port,
            30000,
            "Core destination media port should match 200 OK SDP m=audio"
        )
        
        # 8. Log lines (optional - verify that log was generated)
        self.assertGreater(len(ctx.log_lines), 0, "Should have generated log lines")
        
        print("\n" + "="*70)
        print("✅ TEST PASSED: Inbound 1 Call-ID Without RTP Engine")
        print("="*70)
        print(f"Direction: {ctx.direction}")
        print(f"Call IDs: {ctx.call_ids}")
        print(f"RTP Engine detected: {ctx.rtp_engine.detected}")
        print(f"\nCarrier Leg:")
        print(f"  Source: {ctx.carrier_leg.source_ip} → {ctx.carrier_leg.destination_ip}")
        print(f"  Media: {ctx.carrier_leg.source_media.rtp_ip}:{ctx.carrier_leg.source_media.rtp_port}")
        print(f"      → {ctx.carrier_leg.destination_media.rtp_ip}:{ctx.carrier_leg.destination_media.rtp_port}")
        print(f"\nCore Leg:")
        print(f"  Source: {ctx.core_leg.source_ip} → {ctx.core_leg.destination_ip}")
        print(f"  Media: {ctx.core_leg.source_media.rtp_ip}:{ctx.core_leg.source_media.rtp_port}")
        print(f"      → {ctx.core_leg.destination_media.rtp_ip}:{ctx.core_leg.destination_media.rtp_port}")
        print("="*70 + "\n")

    def test_inbound_single_callid_no_engine_with_use_case_detection(self):
        """
        Test that InboundPSTNCarrierCorrelator is selected for this scenario.
        
        This validates Phase 2 implementation where specific correlators
        are automatically selected based on headers and direction.
        """
        from rtphelper.services.sip_correlation import (
            identify_use_case,
            USE_CASE_HANDLERS,
            InboundPSTNCarrierCorrelator,
        )
        
        call = MockSipCall(call_id="single-inbound-123")
        call.messages = [
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="203.0.113.50",
                dst_ip="10.20.30.100",
                is_request=True,
                method="INVITE",
                call_id="single-inbound-123",
                has_sdp=True,
                headers=["Diversion: <sip:+15551234567@carrier.example.com>"],
                media_sections=[MockMediaSection(connection_ip="203.0.113.50", port=20000)],
            ),
        ]
        
        # Test use case detection
        use_case = identify_use_case(call, "inbound")
        self.assertEqual(
            use_case,
            "inbound_pstn_carrier",
            "Should detect 'inbound_pstn_carrier' use case based on Diversion header"
        )
        
        # Test correlator selection
        handler = USE_CASE_HANDLERS.get(use_case)
        self.assertIsNotNone(handler, "Handler should exist for detected use case")
        self.assertIsInstance(
            handler,
            InboundPSTNCarrierCorrelator,
            "Should use InboundPSTNCarrierCorrelator for this scenario"
        )
        
        print("\n✅ Use case detection test passed:")
        print(f"   Detected: {use_case}")
        print(f"   Correlator: {handler.__class__.__name__}")


def main():
    """Execute tests standalone."""
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestInboundSingleCallIDNoEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
