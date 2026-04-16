#!/usr/bin/env python3
"""
Quick test script to reproduce the exact correlation error.

Run with actual PCAP files to see the exact error that causes fallback to legacy method.

Usage from project root:
    python scripts/quick_correlation_test.py
"""

import sys
from pathlib import Path

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_with_mock_pcap():
    """Test correlation with a mock PCAP structure."""
    print("="*80)
    print("CORRELATION ERROR REPRODUCTION TEST")
    print("="*80)
    print()
    
    from dataclasses import dataclass, field
    from typing import List, Optional, Dict, Set, Tuple
    
    @dataclass
    class MockMediaSection:
        media_type: str = "audio"
        port: int = 5060
        protocol: str = "RTP/SAVP"
        connection_ip: Optional[str] = None
        payload_types: List[str] = field(default_factory=list)
        ssrcs: Set[int] = field(default_factory=set)
        sdes_cryptos: List = field(default_factory=list)
    
    @dataclass
    class MockSipMessage:
        packet_number: int
        ts: float
        src_ip: str
        dst_ip: str
        proto: str = "UDP"
        is_request: bool = True
        method: Optional[str] = None
        status_code: Optional[int] = None
        call_id: Optional[str] = None
        has_sdp: bool = False
        media_sections: List[MockMediaSection] = field(default_factory=list)
        cseq_num: Optional[int] = None
        cseq_method: Optional[str] = None
        via_branch: Optional[str] = None
        to_tag: Optional[str] = None
        from_tag: Optional[str] = None
        other_leg_call_id: Optional[str] = None
        headers: Dict[str, str] = field(default_factory=dict)
    
    @dataclass
    class MockSipCall:
        call_id: str
        messages: List[MockSipMessage] = field(default_factory=list)
        media_sections: List[MockMediaSection] = field(default_factory=list)
        transport_tuples: Set[Tuple] = field(default_factory=set)
    
    @dataclass
    class MockSipParseResult:
        calls: Dict[str, MockSipCall] = field(default_factory=dict)
        warnings: List[str] = field(default_factory=list)
    
    # Create mock inbound call (similar to in-1leg.pcap)
    print("Creating mock inbound call...")
    media = MockMediaSection(
        media_type="audio",
        port=42695,
        protocol="RTP/SAVP",
        connection_ip="65.114.241.40"
    )
    
    invite = MockSipMessage(
        packet_number=1,
        ts=1.0,
        src_ip="65.114.241.40",  # Carrier
        dst_ip="52.40.181.128",   # Core
        is_request=True,
        method="INVITE",
        call_id="test-call-id@test",
        has_sdp=True,
        media_sections=[media],
        cseq_num=1,
        cseq_method="INVITE",
        via_branch="z9hG4bK-test",
        from_tag="carrier-tag"
    )
    
    ok_200 = MockSipMessage(
        packet_number=9,
        ts=2.0,
        src_ip="52.40.181.128",   # Core
        dst_ip="65.114.241.40",    # Carrier
        is_request=False,
        status_code=200,
        call_id="test-call-id@test",
        has_sdp=True,
        media_sections=[media],
        cseq_num=1,
        cseq_method="INVITE",
        via_branch="z9hG4bK-test",
        to_tag="core-tag"
    )
    
    call = MockSipCall(
        call_id="test-call-id@test",
        messages=[invite, ok_200],
        media_sections=[media]
    )
    
    parsed = MockSipParseResult(calls={"test-call-id@test": call})
    
    print("✅ Mock PCAP created")
    print(f"   Call-ID: {call.call_id}")
    print(f"   Messages: {len(call.messages)}")
    print(f"   Carrier IP: {invite.src_ip}")
    print(f"   Core IP: {invite.dst_ip}")
    print()
    
    # Now try to correlate
    print("TESTING CORRELATION")
    print("-"*80)
    
    try:
        from rtphelper.services.sip_correlation import correlate_sip_call
        
        ctx, merged_call = correlate_sip_call(parsed, "inbound")
        
        print("✅ CORRELATION SUCCESSFUL!")
        print(f"   Direction: {ctx.direction}")
        print(f"   Call-IDs: {ctx.call_ids}")
        print(f"   Carrier leg type: {ctx.carrier_leg.leg_type if ctx.carrier_leg else 'None'}")
        print(f"   Core leg type: {ctx.core_leg.leg_type if ctx.core_leg else 'None'}")
        print()
        
        if ctx.log_lines:
            print("   Correlation log lines:")
            for line in ctx.log_lines:
                print(f"     {line}")
        
        print()
        print("="*80)
        print("✅ TEST PASSED - Correlation works with current code!")
        print("="*80)
        print()
        print("If the app still fails but this test passes:")
        print("  1. The app might be using cached .pyc bytecode")
        print("  2. The app might be in a different Python environment")
        print("  3. Check server logs (not UI logs) for the actual exception")
        print()
        print("To verify the app is using the fixed code:")
        print("  1. find rtphelper -name '*.pyc' -delete")
        print("  2. ps aux | grep 'python.*uvicorn' and kill all")
        print("  3. source .venv/bin/activate (if using venv)")
        print("  4. ./scripts/run.sh")
        print("  5. Check logs at: tail -f nohup.out")
        print()
        return 0
        
    except Exception as e:
        print(f"❌ CORRELATION FAILED!")
        print(f"   Error type: {type(e).__name__}")
        print(f"   Error: {e}")
        print()
        
        import traceback
        print("   Full traceback:")
        traceback.print_exc()
        print()
        
        print("="*80)
        print("❌ TEST FAILED - This is the error causing fallback!")
        print("="*80)
        print()
        print("This error should match what appears in the server logs as:")
        print("  WARNING | New correlation failed, falling back to legacy method: <error>")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(test_with_mock_pcap())
