"""
Unit tests for the SIP correlation service.
"""
from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

# Mock the SipMessage and SipCall classes for testing without scapy dependency
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


@dataclass
class MockSipCall:
    call_id: str
    media_sections: List[MockMediaSection] = field(default_factory=list)
    transport_tuples: Set[Tuple[str, int, str, int, str]] = field(default_factory=set)
    messages: List[MockSipMessage] = field(default_factory=list)


@dataclass
class MockSipParseResult:
    calls: dict = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


class TestSipCorrelation(unittest.TestCase):
    """Test SIP correlation logic."""

    def test_group_related_calls_single_call(self):
        """Test grouping with a single call ID."""
        from rtphelper.services.sip_correlation import group_related_calls
        
        # Create mock result with single call
        result = MockSipParseResult()
        call1 = MockSipCall(call_id="call-1")
        call1.messages = [
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                is_request=True,
                method="INVITE",
                call_id="call-1",
            )
        ]
        result.calls = {"call-1": call1}
        
        groups = group_related_calls(result)
        
        self.assertEqual(len(groups), 1)
        self.assertIn("call-1", groups[0])

    def test_group_related_calls_with_other_leg(self):
        """Test grouping calls connected by X-Talkdesk-Other-Leg-Call-Id."""
        from rtphelper.services.sip_correlation import group_related_calls
        
        result = MockSipParseResult()
        
        # Call 1 references Call 2 via X-Talkdesk-Other-Leg-Call-Id
        call1 = MockSipCall(call_id="call-1")
        call1.messages = [
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                is_request=True,
                method="INVITE",
                call_id="call-1",
                other_leg_call_id="call-2",
            )
        ]
        
        call2 = MockSipCall(call_id="call-2")
        call2.messages = [
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.3",
                is_request=True,
                method="INVITE",
                call_id="call-2",
            )
        ]
        
        result.calls = {"call-1": call1, "call-2": call2}
        
        groups = group_related_calls(result)
        
        # Both calls should be in the same group
        self.assertEqual(len(groups), 1)
        self.assertIn("call-1", groups[0])
        self.assertIn("call-2", groups[0])

    def test_merge_calls_by_group(self):
        """Test merging multiple calls."""
        from rtphelper.services.sip_correlation import merge_calls_by_group
        
        result = MockSipParseResult()
        
        call1 = MockSipCall(call_id="call-1")
        call1.messages = [
            MockSipMessage(packet_number=1, ts=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        ]
        call1.media_sections = [MockMediaSection(connection_ip="1.2.3.4", port=5060)]
        
        call2 = MockSipCall(call_id="call-2")
        call2.messages = [
            MockSipMessage(packet_number=2, ts=2.0, src_ip="10.0.0.2", dst_ip="10.0.0.3")
        ]
        call2.media_sections = [MockMediaSection(connection_ip="5.6.7.8", port=5062)]
        
        result.calls = {"call-1": call1, "call-2": call2}
        
        merged = merge_calls_by_group(result, {"call-1", "call-2"})
        
        # Merged call should have messages from both
        self.assertEqual(len(merged.messages), 2)
        self.assertEqual(len(merged.media_sections), 2)

    def test_merge_single_call_returns_original(self):
        """Test that merging a single call returns the original."""
        from rtphelper.services.sip_correlation import merge_calls_by_group
        
        result = MockSipParseResult()
        
        call1 = MockSipCall(call_id="call-1")
        call1.messages = [
            MockSipMessage(packet_number=1, ts=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        ]
        result.calls = {"call-1": call1}
        
        merged = merge_calls_by_group(result, {"call-1"})
        
        # Should return the original call
        self.assertEqual(merged.call_id, "call-1")


class TestRtpEngineDetection(unittest.TestCase):
    """Test RTP Engine detection logic."""

    def test_no_rtp_engine_single_hop(self):
        """Test detection when there's no RTP engine (single hop)."""
        from rtphelper.services.sip_correlation import detect_rtp_engine
        
        call = MockSipCall(call_id="test")
        call.messages = [
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                is_request=True,
                method="INVITE",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="192.168.1.1", port=5060)],
            )
        ]
        
        info = detect_rtp_engine(call, "inbound")
        
        self.assertFalse(info.detected)
        self.assertIsNone(info.engine_ip)

    def test_rtp_engine_detected_sdp_change(self):
        """Test RTP engine detection when SDP c= changes across hops."""
        from rtphelper.services.sip_correlation import detect_rtp_engine
        
        call = MockSipCall(call_id="test")
        call.messages = [
            # First INVITE with original RTP IP
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                is_request=True,
                method="INVITE",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="192.168.1.1", port=5060)],
            ),
            # Second INVITE with changed RTP IP (from RTP engine)
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="10.0.0.2",  # This is the RTP engine
                dst_ip="10.0.0.3",
                is_request=True,
                method="INVITE",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="10.0.0.100", port=5060)],  # Different IP!
            ),
        ]
        
        info = detect_rtp_engine(call, "inbound")
        
        self.assertTrue(info.detected)
        self.assertEqual(info.engine_ip, "10.0.0.2")


class TestBuildCorrelationContext(unittest.TestCase):
    """Test building the full correlation context."""

    def test_inbound_direction(self):
        """Test correlation context for inbound call."""
        from rtphelper.services.sip_correlation import build_correlation_context
        
        call = MockSipCall(call_id="test-inbound")
        
        # Inbound: Carrier -> B2BUA -> Core
        call.messages = [
            # First INVITE from carrier
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="1.1.1.1",  # Carrier
                dst_ip="10.0.0.1",  # B2BUA
                is_request=True,
                method="INVITE",
                from_tag="tag1",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="1.1.1.100", port=10000)],
            ),
            # INVITE forwarded to core
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="10.0.0.1",  # B2BUA
                dst_ip="2.2.2.2",  # Core
                is_request=True,
                method="INVITE",
                from_tag="tag1",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="10.0.0.100", port=10002)],
            ),
            # 200 OK from core
            MockSipMessage(
                packet_number=3,
                ts=3.0,
                src_ip="2.2.2.2",  # Core
                dst_ip="10.0.0.1",  # B2BUA
                is_request=False,
                status_code=200,
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="2.2.2.100", port=10004)],
            ),
            # 200 OK to carrier
            MockSipMessage(
                packet_number=4,
                ts=4.0,
                src_ip="10.0.0.1",  # B2BUA
                dst_ip="1.1.1.1",  # Carrier
                is_request=False,
                status_code=200,
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="10.0.0.200", port=10006)],
            ),
        ]
        
        ctx = build_correlation_context(call, "inbound", ["test-inbound"])
        
        self.assertEqual(ctx.direction, "inbound")
        self.assertIsNotNone(ctx.carrier_leg)
        self.assertIsNotNone(ctx.core_leg)
        self.assertEqual(ctx.carrier_leg.source_ip, "1.1.1.1")  # Carrier IP

    def test_outbound_direction(self):
        """Test correlation context for outbound call."""
        from rtphelper.services.sip_correlation import build_correlation_context
        
        call = MockSipCall(call_id="test-outbound")
        
        # Outbound: Core -> B2BUA -> Carrier
        call.messages = [
            # First INVITE from core
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="2.2.2.2",  # Core
                dst_ip="10.0.0.1",  # B2BUA
                is_request=True,
                method="INVITE",
                from_tag="tag1",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="2.2.2.100", port=10000)],
            ),
            # INVITE forwarded to carrier
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="10.0.0.1",  # B2BUA
                dst_ip="1.1.1.1",  # Carrier
                is_request=True,
                method="INVITE",
                from_tag="tag1",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="10.0.0.100", port=10002)],
            ),
            # 200 OK from carrier
            MockSipMessage(
                packet_number=3,
                ts=3.0,
                src_ip="1.1.1.1",  # Carrier
                dst_ip="10.0.0.1",  # B2BUA
                is_request=False,
                status_code=200,
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="1.1.1.100", port=10004)],
            ),
        ]
        
        ctx = build_correlation_context(call, "outbound", ["test-outbound"])
        
        self.assertEqual(ctx.direction, "outbound")
        self.assertIsNotNone(ctx.carrier_leg)
        self.assertIsNotNone(ctx.core_leg)
        self.assertEqual(ctx.core_leg.source_ip, "2.2.2.2")  # Core IP


class TestSpecificCorrelators(unittest.TestCase):
    """Test Phase 2 specific correlators."""

    def test_inbound_pstn_correlator_exists(self):
        """Test that InboundPSTNCarrierCorrelator is available."""
        from rtphelper.services.sip_correlation import (
            InboundPSTNCarrierCorrelator,
            CorrelationStrategy,
        )
        
        correlator = InboundPSTNCarrierCorrelator()
        self.assertIsInstance(correlator, CorrelationStrategy)
        self.assertTrue(hasattr(correlator, "correlate"))

    def test_outbound_pstn_correlator_exists(self):
        """Test that OutboundPSTNCarrierCorrelator is available."""
        from rtphelper.services.sip_correlation import (
            OutboundPSTNCarrierCorrelator,
            CorrelationStrategy,
        )
        
        correlator = OutboundPSTNCarrierCorrelator()
        self.assertIsInstance(correlator, CorrelationStrategy)
        self.assertTrue(hasattr(correlator, "correlate"))

    def test_use_case_handlers_registry(self):
        """Test that USE_CASE_HANDLERS registry has specific correlators."""
        from rtphelper.services.sip_correlation import (
            USE_CASE_HANDLERS,
            GenericCorrelator,
            InboundPSTNCarrierCorrelator,
            OutboundPSTNCarrierCorrelator,
        )
        
        # Verify registry has expected keys
        self.assertIn("unknown", USE_CASE_HANDLERS)
        self.assertIn("inbound_pstn_carrier", USE_CASE_HANDLERS)
        self.assertIn("outbound_pstn_carrier", USE_CASE_HANDLERS)
        
        # Verify handler types
        self.assertIsInstance(USE_CASE_HANDLERS["unknown"], GenericCorrelator)
        self.assertIsInstance(USE_CASE_HANDLERS["inbound_pstn_carrier"], InboundPSTNCarrierCorrelator)
        self.assertIsInstance(USE_CASE_HANDLERS["outbound_pstn_carrier"], OutboundPSTNCarrierCorrelator)

    def test_inbound_correlator_produces_context(self):
        """Test that InboundPSTNCarrierCorrelator produces valid CorrelationContext."""
        from rtphelper.services.sip_correlation import InboundPSTNCarrierCorrelator
        
        correlator = InboundPSTNCarrierCorrelator()
        
        # Create minimal mock call
        call = MockSipCall(call_id="test-inbound")
        call.messages = [
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                is_request=True,
                method="INVITE",
                call_id="test-inbound",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="1.1.1.1", port=5060)],
            ),
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="2.2.2.2",
                dst_ip="1.1.1.1",
                is_request=False,
                status_code=200,
                cseq_method="INVITE",
                call_id="test-inbound",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="2.2.2.2", port=5062)],
            ),
        ]
        
        ctx = correlator.correlate(call, "inbound", ["test-inbound"])
        
        # Verify basic context structure
        self.assertEqual(ctx.direction, "inbound")
        self.assertEqual(ctx.call_ids, ["test-inbound"])
        
        # Verify correlator annotation was added
        self.assertTrue(
            any("InboundPSTNCarrierCorrelator" in line for line in ctx.log_lines),
            f"Expected correlator annotation in logs: {ctx.log_lines}"
        )

    def test_outbound_correlator_produces_context(self):
        """Test that OutboundPSTNCarrierCorrelator produces valid CorrelationContext."""
        from rtphelper.services.sip_correlation import OutboundPSTNCarrierCorrelator
        
        correlator = OutboundPSTNCarrierCorrelator()
        
        # Create minimal mock call
        call = MockSipCall(call_id="test-outbound")
        call.messages = [
            MockSipMessage(
                packet_number=1,
                ts=1.0,
                src_ip="2.2.2.2",
                dst_ip="1.1.1.1",
                is_request=True,
                method="INVITE",
                call_id="test-outbound",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="2.2.2.2", port=5060)],
            ),
            MockSipMessage(
                packet_number=2,
                ts=2.0,
                src_ip="1.1.1.1",
                dst_ip="2.2.2.2",
                is_request=False,
                status_code=200,
                cseq_method="INVITE",
                call_id="test-outbound",
                has_sdp=True,
                media_sections=[MockMediaSection(connection_ip="1.1.1.1", port=5062)],
            ),
        ]
        
        ctx = correlator.correlate(call, "outbound", ["test-outbound"])
        
        # Verify basic context structure
        self.assertEqual(ctx.direction, "outbound")
        self.assertEqual(ctx.call_ids, ["test-outbound"])
        
        # Verify correlator annotation was added
        self.assertTrue(
            any("OutboundPSTNCarrierCorrelator" in line for line in ctx.log_lines),
            f"Expected correlator annotation in logs: {ctx.log_lines}"
        )


if __name__ == "__main__":
    unittest.main()

