#!/usr/bin/env python3
"""Direct test of _find_response_to_hop function."""

import sys
from pathlib import Path
sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from rtphelper.services.sip_parser import parse_sip_pcap, SipCall
from rtphelper.services.sip_correlation import _find_response_to_hop, group_related_calls

def test_find_response_to_hop(pcap_path):
    """Test _find_response_to_hop directly."""
    print("\n" + "="*80)
    print("DIRECT TEST: _find_response_to_hop")
    print("="*80 + "\n")
    
    result = parse_sip_pcap(Path(pcap_path))
    
    # Merge calls
    groups = group_related_calls(result)
    call_ids = list(groups[0])
    
    # Create merged SipCall
    all_messages = []
    for cid in call_ids:
        if cid in result.calls:
            all_messages.extend(result.calls[cid].messages)
    
    # Create a fake SipCall with merged messages
    merged_call = SipCall(call_id=";".join(call_ids))
    merged_call.messages = sorted(all_messages, key=lambda m: m.ts)
    
    print(f"Merged call has {len(merged_call.messages)} messages")
    print(f"Call-IDs: {call_ids}\n")
    
    # Find first INVITE
    invites = [m for m in merged_call.messages if m.is_request and (m.method or "").upper() == "INVITE"]
    first_invite = invites[0]
    
    print(f"First INVITE: packet {first_invite.packet_number}, {first_invite.src_ip} → {first_invite.dst_ip}")
    print(f"Timestamp: {first_invite.ts}\n")
    
    # Test _find_response_to_hop
    next_hop = first_invite.dst_ip
    print(f"Calling _find_response_to_hop(call, hop_ip={next_hop}, after_ts={first_invite.ts})\n")
    
    response = _find_response_to_hop(merged_call, next_hop, first_invite.ts)
    
    if response:
        print(f"✓ FOUND RESPONSE!")
        print(f"  Packet: {response.packet_number}")
        print(f"  Status: {response.status_code}")
        print(f"  {response.src_ip} → {response.dst_ip}")
        print(f"  has_sdp: {response.has_sdp}")
        print(f"  media_sections: {len(response.media_sections)}")
        for ms in response.media_sections:
            print(f"    - {ms.media_type} port {ms.port}")
        print(f"  Call-ID: {response.call_id}")
    else:
        print(f"✗ NO RESPONSE FOUND")
        print(f"\nDEBUGGING: Let's trace through the function manually...")
        
        # Find INVITEs sent BY next_hop
        invites_from_hop = [
            m for m in merged_call.messages
            if (m.is_request
                and (m.method or "").upper() == "INVITE"
                and m.src_ip == next_hop
                and m.ts >= first_invite.ts)
        ]
        
        print(f"\nINVITEs sent BY {next_hop}: {len(invites_from_hop)}")
        for inv in invites_from_hop:
            print(f"  Packet {inv.packet_number}: {inv.src_ip} → {inv.dst_ip}")
            print(f"    Call-ID: {inv.call_id}")
            print(f"    CSeq: {inv.cseq_num}")
            
            # Try _find_response_for_invite_with_priority directly
            from rtphelper.services.sip_correlation import _find_response_for_invite_with_priority
            resp = _find_response_for_invite_with_priority(merged_call, inv)
            if resp:
                print(f"    → Found response: packet {resp.packet_number}, status {resp.status_code}")
            else:
                print(f"    → No response found by _find_response_for_invite_with_priority")
                
                # Try _find_183_progress_with_sdp_for_invite directly
                from rtphelper.services.sip_correlation import _find_183_progress_with_sdp_for_invite
                resp_183 = _find_183_progress_with_sdp_for_invite(merged_call, inv)
                if resp_183:
                    print(f"       _find_183: packet {resp_183.packet_number}")
                else:
                    print(f"       _find_183: None")
                
                # Try _find_200ok_for_invite directly
                from rtphelper.services.sip_correlation import _find_200ok_for_invite
                resp_200 = _find_200ok_for_invite(merged_call, inv)
                if resp_200:
                    print(f"       _find_200: packet {resp_200.packet_number}")
                else:
                    print(f"       _find_200: None")

if __name__ == "__main__":
    pcap = "/Users/fdanielneto/Downloads/prd-eu-test2/20260304_095832/uploads/noetica-in-2leg.pcap"
    test_find_response_to_hop(pcap)
