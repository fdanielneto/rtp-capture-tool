#!/usr/bin/env python3
"""Test correlation with detailed debug output for carrier fallback logic."""

import sys
sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from pathlib import Path
from rtphelper.services.sip_parser import parse_sip_pcap


def test_fallback_debug(pcap_path, direction):
    """Test with detailed debug output."""
    print(f"\n{'='*80}")
    print(f"DEBUG ANALYSIS: {direction.upper()}")
    print(f"PCAP: {pcap_path}")
    print(f"{'='*80}\n")
    
    # Parse SIP
    result = parse_sip_pcap(Path(pcap_path))
    print(f"Parsed calls: {len(result.calls)}")
    
    # Get the merged call
    call = None
    for c in result.calls.values():
        call = c
        break
    
    if not call:
        print("No calls found!")
        return
    
    print(f"\nTotal messages in call: {len(call.messages)}")
    
    # Find first INVITE
    invites = [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
    invites.sort(key=lambda m: m.ts)
    
    if not invites:
        print("No INVITEs found!")
        return
    
    first_invite = invites[0]
    print(f"\n--- FIRST INVITE (packet {first_invite.packet_number}) ---")
    print(f"  FROM: {first_invite.src_ip}")
    print(f"  TO: {first_invite.dst_ip}")
    print(f"  first_hop (dst_ip): {first_invite.dst_ip}")
    
    # Find all messages involving the first hop as destination (INVITEs TO first_hop)
    first_hop = first_invite.dst_ip
    print(f"\n--- INVITES TO first_hop ({first_hop}) ---")
    invites_to_hop = [
        m for m in call.messages
        if m.is_request and (m.method or "").upper() == "INVITE" and m.dst_ip == first_hop
    ]
    for inv in invites_to_hop:
        print(f"  Packet {inv.packet_number}: {inv.src_ip} -> {inv.dst_ip} (ts={inv.ts:.3f})")
    
    # Find all responses FROM first hop
    print(f"\n--- RESPONSES FROM first_hop ({first_hop}) ---")
    responses_from_hop = [
        m for m in call.messages
        if not m.is_request and m.src_ip == first_hop
    ]
    for resp in responses_from_hop:
        print(f"  Packet {resp.packet_number}: {resp.src_ip} -> {resp.dst_ip} "
              f"status={resp.status_code} has_sdp={resp.has_sdp} (ts={resp.ts:.3f})")
    
    # For each INVITE to first hop, look for matching responses
    print(f"\n--- RESPONSE MATCHING ---")
    for inv in invites_to_hop:
        print(f"\nFor INVITE packet {inv.packet_number} ({inv.src_ip} -> {inv.dst_ip}):")
        print(f"  Looking for response: FROM {inv.dst_ip} TO {inv.src_ip}, ts >= {inv.ts:.3f}")
        
        # Find 183 candidates
        candidates_183 = [
            m for m in call.messages
            if (not m.is_request
                and m.status_code == 183
                and m.src_ip == inv.dst_ip
                and m.dst_ip == inv.src_ip
                and m.ts >= inv.ts
                and (m.ts - inv.ts) <= 180.0)
        ]
        
        # Find 200 OK candidates
        candidates_200 = [
            m for m in call.messages
            if (not m.is_request
                and m.status_code == 200
                and m.src_ip == inv.dst_ip
                and m.dst_ip == inv.src_ip
                and m.ts >= inv.ts
                and (m.ts - inv.ts) <= 180.0)
        ]
        
        print(f"  183 candidates: {len(candidates_183)}")
        for c in candidates_183:
            print(f"    Packet {c.packet_number}: has_sdp={c.has_sdp}")
        
        print(f"  200 OK candidates: {len(candidates_200)}")
        for c in candidates_200:
            print(f"    Packet {c.packet_number}: has_sdp={c.has_sdp}")
        
        if not candidates_183 and not candidates_200:
            print(f"  ❌ NO RESPONSES FOUND")
    
    # Show what responses DO exist
    print(f"\n--- ALL RESPONSES IN CALL ---")
    all_responses = [m for m in call.messages if not m.is_request]
    for resp in all_responses:
        print(f"  Packet {resp.packet_number}: {resp.src_ip} -> {resp.dst_ip} "
              f"status={resp.status_code} has_sdp={resp.has_sdp}")


if __name__ == "__main__":
    pcap = "/Users/fdanielneto/Downloads/prd-eu-test2/20260304_095832/uploads/noetica-in-2leg.pcap"
    
    print("\n" + "#"*80)
    print("# INBOUND DIRECTION - CARRIER FALLBACK ANALYSIS")
    print("#"*80)
    test_fallback_debug(pcap, "inbound")
