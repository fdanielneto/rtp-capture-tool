#!/usr/bin/env python3
"""Test correlation with the new 183/200 OK fallback logic."""

import sys
sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from pathlib import Path
from rtphelper.services.sip_parser import parse_sip_pcap
from rtphelper.services.sip_correlation import correlate_sip_call

def test_correlation(pcap_path, direction):
    """Test correlation with new implementation."""
    print(f"\n{'='*80}")
    print(f"Testing Correlation: {direction.upper()}")
    print(f"PCAP: {pcap_path}")
    print(f"{'='*80}\n")
    
    # Parse SIP
    result = parse_sip_pcap(Path(pcap_path))
    print(f"Parsed calls: {len(result.calls)}")
    
    # Get Call-IDs
    call_ids = list(result.calls.keys())
    print(f"Call-IDs: {'; '.join(call_ids)}\n")
    
    # Build correlation context
    context, merged_call = correlate_sip_call(
        parse_result=result,
        direction=direction,
        primary_call_id=None
    )
    
    print("\n" + "="*80)
    print("CORRELATION CONTEXT:")
    print("="*80)
    
    print(f"\nDirection: {context.direction}")
    print(f"Call-IDs: {'; '.join(context.call_ids)}")
    print(f"RTP Engine detected: {context.rtp_engine.detected}")
    
    if context.carrier_leg:
        print(f"\n--- CARRIER LEG ---")
        print(f"  Type: {context.carrier_leg.leg_type}")
        print(f"  Source: {context.carrier_leg.source_ip}")
        print(f"  Destination: {context.carrier_leg.destination_ip}")
        print(f"  INVITE packet: {context.carrier_leg.invite_packet}")
        print(f"  200 OK packet: {context.carrier_leg.ok_200_packet}")
        if context.carrier_leg.source_media:
            print(f"  Source media: {context.carrier_leg.source_media.rtp_ip}:{context.carrier_leg.source_media.rtp_port} (packet {context.carrier_leg.source_media.packet_number}, method={context.carrier_leg.source_media.method})")
        if context.carrier_leg.destination_media:
            print(f"  Dest media: {context.carrier_leg.destination_media.rtp_ip}:{context.carrier_leg.destination_media.rtp_port} (packet {context.carrier_leg.destination_media.packet_number}, method={context.carrier_leg.destination_media.method})")
    
    if context.core_leg:
        print(f"\n--- CORE LEG ---")
        print(f"  Type: {context.core_leg.leg_type}")
        print(f"  Source: {context.core_leg.source_ip}")
        print(f"  Destination: {context.core_leg.destination_ip}")
        print(f"  INVITE packet: {context.core_leg.invite_packet}")
        print(f"  200 OK packet: {context.core_leg.ok_200_packet}")
        if context.core_leg.source_media:
            print(f"  Source media: {context.core_leg.source_media.rtp_ip}:{context.core_leg.source_media.rtp_port} (packet {context.core_leg.source_media.packet_number}, method={context.core_leg.source_media.method})")
        if context.core_leg.destination_media:
            print(f"  Dest media: {context.core_leg.destination_media.rtp_ip}:{context.core_leg.destination_media.rtp_port} (packet {context.core_leg.destination_media.packet_number}, method={context.core_leg.destination_media.method})")
    
    print("\n" + "="*80)
    print("LOG LINES:")
    print("="*80)
    for line in context.log_lines:
        print(line)
    
    print("\n" + "="*80)
    print("SUCCESS!" if (context.carrier_leg and context.core_leg) else "FAILED!")
    print("="*80)
    
    return context

if __name__ == "__main__":
    pcap = "/Users/fdanielneto/Downloads/prd-eu-test2/20260304_095832/uploads/noetica-in-2leg.pcap"
    
    print("\n\n" + "#"*80)
    print("# TEST 1: INBOUND DIRECTION")
    print("#"*80)
    ctx_inbound = test_correlation(pcap, "inbound")
    
    print("\n\n" + "#"*80)
    print("# TEST 2: OUTBOUND DIRECTION")
    print("#"*80)
    ctx_outbound = test_correlation(pcap, "outbound")
    
    print("\n\n" + "#"*80)
    print("# SUMMARY")
    print("#"*80)
    print(f"INBOUND carrier leg: {'✓ OK' if ctx_inbound.carrier_leg and ctx_inbound.carrier_leg.ok_200_packet else '✗ FAILED'}")
    print(f"INBOUND core leg: {'✓ OK' if ctx_inbound.core_leg and ctx_inbound.core_leg.ok_200_packet else '✗ FAILED'}")
    print(f"OUTBOUND carrier leg: {'✓ OK' if ctx_outbound.carrier_leg and ctx_outbound.carrier_leg.ok_200_packet else '✗ FAILED'}")
    print(f"OUTBOUND core leg: {'✓ OK' if ctx_outbound.core_leg and ctx_outbound.core_leg.ok_200_packet else '✗ FAILED'}")
