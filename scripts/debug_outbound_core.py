#!/usr/bin/env python3
"""Debug OUTBOUND core leg fallback."""

import sys
sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from pathlib import Path
from rtphelper.services.sip_parser import parse_sip_pcap

def debug_outbound_core(pcap_path):
    """Debug why OUTBOUND core leg fallback doesn't find response."""
    print("\n" + "="*80)
    print("DEBUG: OUTBOUND Core Leg Fallback")
    print("="*80 + "\n")
    
    result = parse_sip_pcap(Path(pcap_path))
    
    # Merge calls (simulate what build_correlation_context does)
    from rtphelper.services.sip_correlation import group_related_calls
    groups = group_related_calls(result)
    
    # Take first group (both Call-IDs merged)
    call_ids = list(groups[0])
    print(f"Call-IDs in group: {call_ids}\n")
    
    # Merge messages from both calls
    all_messages = []
    for cid in call_ids:
        if cid in result.calls:
            all_messages.extend(result.calls[cid].messages)
    
    all_messages.sort(key=lambda m: m.ts)
    
    # Find first INVITE
    invites = [m for m in all_messages if m.is_request and (m.method or "").upper() == "INVITE"]
    first_invite = invites[0]
    
    print(f"First INVITE (core sends):")
    print(f"  Packet: {first_invite.packet_number}")
    print(f"  {first_invite.src_ip} → {first_invite.dst_ip}")
    print(f"  Timestamp: {first_invite.ts}")
    print(f"  CSeq: {first_invite.cseq_num}")
    print(f"  Via: {first_invite.via_branch[:40] if first_invite.via_branch else None}...")
    print()
    
    # Find next hop (first_invite.dst_ip = 10.95.5.198)
    next_hop = first_invite.dst_ip
    print(f"Next hop IP: {next_hop}\n")
    
    # Find INVITEs sent BY next_hop
    print("INVITEs sent BY next_hop:")
    invites_from_hop = [
        m for m in all_messages
        if (m.is_request
            and (m.method or "").upper() == "INVITE"
            and m.src_ip == next_hop
            and m.ts >= first_invite.ts)
    ]
    for inv in invites_from_hop:
        print(f"  Packet {inv.packet_number}: {inv.src_ip} → {inv.dst_ip}, ts={inv.ts:.3f}")
        print(f"    CSeq: {inv.cseq_num}, Via: {inv.via_branch[:40] if inv.via_branch else None}...")
        print(f"    Call-ID: {inv.call_id}")
    print()
    
    # For each INVITE, find 183/200 responses
    print("Responses to those INVITEs:")
    for inv in invites_from_hop:
        print(f"\n  For INVITE packet {inv.packet_number} ({inv.src_ip} → {inv.dst_ip}):")
        
        # Look for 183
        responses_183 = [
            m for m in all_messages
            if (not m.is_request
                and m.status_code == 183
                and m.src_ip == inv.dst_ip
                and m.dst_ip == inv.src_ip
                and m.ts >= inv.ts
                and (m.ts - inv.ts) <= 180.0)
        ]
        
        print(f"    183 candidates: {len(responses_183)}")
        for r in responses_183:
            print(f"      Packet {r.packet_number}: {r.src_ip} → {r.dst_ip}")
            print(f"        has_sdp={r.has_sdp}")
            print(f"        CSeq: {r.cseq_num}, Via: {r.via_branch[:40] if r.via_branch else None}...")
            print(f"        Call-ID: {r.call_id}")
            
            # Check CSeq match
            if inv.cseq_num and r.cseq_num:
                print(f"        CSeq match: {inv.cseq_num == r.cseq_num}")
            # Check Via match
            if inv.via_branch and r.via_branch:
                print(f"        Via match: {inv.via_branch == r.via_branch}")
        
        # Look for 200
        responses_200 = [
            m for m in all_messages
            if (not m.is_request
                and m.status_code == 200
                and m.src_ip == inv.dst_ip
                and m.dst_ip == inv.src_ip
                and m.ts >= inv.ts
                and (m.ts - inv.ts) <= 180.0)
        ]
        
        print(f"    200 OK candidates: {len(responses_200)}")
        for r in responses_200:
            print(f"      Packet {r.packet_number}: {r.src_ip} → {r.dst_ip}")
            print(f"        has_sdp={r.has_sdp}")
            print(f"        Call-ID: {r.call_id}")

if __name__ == "__main__":
    pcap = "/Users/fdanielneto/Downloads/prd-eu-test2/20260304_095832/uploads/noetica-in-2leg.pcap"
    debug_outbound_core(pcap)
