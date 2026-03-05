#!/usr/bin/env python3
"""Quick script to inspect SIP flow in a PCAP file."""

import sys
sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from rtphelper.services.sip_parser import parse_sip_pcap

def inspect_pcap(pcap_path):
    """Parse PCAP and show all SIP messages."""
    print(f"\n=== Inspecting {pcap_path} ===\n")
    
    calls = parse_sip_pcap(pcap_path)
    
    for call in calls:
        print(f"\nCall-ID: {call.call_id}")
        print(f"Messages: {len(call.messages)}")
        print("\n" + "="*80)
        
        for msg in call.messages:
            status_info = ""
            if msg.status_code:
                status_info = f" {msg.status_code} {msg.status_line or ''}"
            
            print(f"#{msg.packet_number:3d} | {msg.timestamp:.3f} | "
                  f"{msg.src_ip:15s}→{msg.dst_ip:15s} | "
                  f"{msg.method or 'RESPONSE'}{status_info}")
            
            if msg.has_sdp:
                print(f"      └─ SDP: {msg.sdp_ip}:{msg.audio_port}")
        
        print("="*80 + "\n")

if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "/Users/fdanielneto/Downloads/prd-eu-test2/20260304_095832/uploads/noetica-in-2leg.pcap"
    inspect_pcap(pcap)
