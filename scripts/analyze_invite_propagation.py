#!/usr/bin/env python3
"""Analyze INVITE propagation chain and response flow."""

import sys
from pathlib import Path

sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from rtphelper.services.sip_parser import parse_sip_pcap

def analyze_invite_chain(pcap_path: str, target_call_id: str = None):
    """Analyze INVITE propagation and response flow."""
    print(f"\n{'='*80}")
    print(f"INVITE PROPAGATION CHAIN ANALYSIS")
    print(f"PCAP: {pcap_path}")
    print(f"{'='*80}\n")
    
    result = parse_sip_pcap(Path(pcap_path))
    
    # Get all calls
    calls = list(result.calls.values())
    print(f"Total calls found: {len(calls)}\n")
    
    for call in calls:
        # Focus on target call if specified
        if target_call_id and target_call_id not in call.call_id:
            continue
            
        print(f"\n{'='*80}")
        print(f"Call-ID: {call.call_id}")
        print(f"Total messages: {len(call.messages)}")
        print(f"{'='*80}\n")
        
        # Extract INVITEs
        invites = [m for m in call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
        invites.sort(key=lambda m: m.ts)
        
        print(f"--- ALL INVITE MESSAGES ({len(invites)}) ---")
        for inv in invites:
            print(f"  Packet {inv.packet_number:3d}: {inv.src_ip:15s} → {inv.dst_ip:15s}")
            print(f"    Timestamp: {inv.ts:.3f}")
            print(f"    CSeq: {inv.cseq_num} {inv.cseq_method}")
            print(f"    Via Branch: {inv.via_branch or '(none)'}")
            print(f"    To Tag: {inv.to_tag or '(none)'} (initial INVITE if none)")
            print(f"    Has SDP: {inv.has_sdp}")
            if inv.has_sdp and inv.media_sections:
                for media in inv.media_sections:
                    if media.media_type == "audio":
                        print(f"    Audio: {media.connection_ip}:{media.port}")
            print()
        
        # Extract 183/200 responses
        responses = [
            m for m in call.messages 
            if not m.is_request and m.status_code in [183, 200]
        ]
        responses.sort(key=lambda m: m.ts)
        
        print(f"\n--- ALL 183/200 RESPONSES ({len(responses)}) ---")
        for resp in responses:
            print(f"  Packet {resp.packet_number:3d}: {resp.src_ip:15s} → {resp.dst_ip:15s} [{resp.status_code}]")
            print(f"    Timestamp: {resp.ts:.3f}")
            print(f"    CSeq: {resp.cseq_num} {resp.cseq_method}")
            print(f"    Via Branch: {resp.via_branch or '(none)'}")
            print(f"    Has SDP: {resp.has_sdp}")
            if resp.has_sdp and resp.media_sections:
                for media in resp.media_sections:
                    if media.media_type == "audio":
                        print(f"    Audio: {media.connection_ip}:{media.port}")
            
            # Try to match to INVITE
            print(f"    Matching INVITE:")
            # Look for INVITE: swapped src/dst, earlier timestamp
            matching = [
                inv for inv in invites
                if inv.dst_ip == resp.src_ip 
                and inv.src_ip == resp.dst_ip
                and inv.ts <= resp.ts
            ]
            
            if matching:
                # Try exact match first
                exact = [
                    inv for inv in matching
                    if inv.cseq_num == resp.cseq_num
                    and inv.via_branch == resp.via_branch
                ]
                if exact:
                    inv = exact[0]
                    print(f"      → EXACT match: Packet {inv.packet_number} (CSeq + Via match)")
                else:
                    # Try CSeq only
                    cseq_match = [inv for inv in matching if inv.cseq_num == resp.cseq_num]
                    if cseq_match:
                        inv = cseq_match[0]
                        print(f"      → CSeq match: Packet {inv.packet_number} (CSeq: {inv.cseq_num})")
                    else:
                        # Fuzzy: closest before this response
                        inv = sorted(matching, key=lambda m: resp.ts - m.ts)[0]
                        print(f"      → FUZZY match: Packet {inv.packet_number} (direction + time)")
            else:
                print(f"      → NO MATCHING INVITE FOUND")
            print()
        
        # Show the propagation chain
        print(f"\n--- INVITE PROPAGATION CHAIN ---")
        if invites:
            first_invite = invites[0]
            print(f"1. INITIAL INVITE:")
            print(f"   Packet {first_invite.packet_number}: {first_invite.src_ip} → {first_invite.dst_ip}")
            print(f"   (Carrier/Origin → First Hop)")
            
            # Look for propagated INVITEs (from first hop to another destination)
            propagated = [
                inv for inv in invites[1:]
                if inv.src_ip == first_invite.dst_ip  # First hop relays
            ]
            
            if propagated:
                print(f"\n2. PROPAGATED INVITE(S):")
                for i, inv in enumerate(propagated, start=1):
                    print(f"   {i}. Packet {inv.packet_number}: {inv.src_ip} → {inv.dst_ip}")
                    print(f"      (First Hop → Next Hop)")
            else:
                print(f"\n2. NO PROPAGATED INVITEs found from {first_invite.dst_ip}")
            
            # Show responses and their direction
            print(f"\n3. RESPONSE FLOW:")
            for resp in responses:
                print(f"   Packet {resp.packet_number}: {resp.src_ip} → {resp.dst_ip} [{resp.status_code}]")
                
                # Determine if this goes TO or FROM the first hop
                if resp.dst_ip == first_invite.dst_ip:
                    print(f"      Direction: Response goes TO first hop ({first_invite.dst_ip})")
                elif resp.src_ip == first_invite.dst_ip:
                    print(f"      Direction: Response goes FROM first hop ({first_invite.dst_ip})")
                else:
                    print(f"      Direction: Response does not involve first hop")
        
        print(f"\n{'='*80}\n")

if __name__ == "__main__":
    pcap = "/Users/fdanielneto/Downloads/prd-eu-test2/20260304_095832/uploads/noetica-in-2leg.pcap"
    target_call = "9d0de9fd-9253-123f-3981-6193760bab69"
    
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    if len(sys.argv) > 2:
        target_call = sys.argv[2]
    
    analyze_invite_chain(pcap, target_call)
