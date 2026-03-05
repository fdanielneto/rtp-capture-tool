#!/usr/bin/env python3
"""Analyze SIP responses in PCAP for debugging correlation."""

import sys
sys.path.insert(0, '/Users/fdanielneto/Documents/github/rtp-capture-tool')

from rtphelper.services.sip_parser import parse_sip_pcap
from pathlib import Path

def analyze_responses(pcap_path):
    """Parse PCAP and analyze all SIP response messages."""
    print(f"\n{'='*80}")
    print(f"Analyzing: {pcap_path}")
    print(f"{'='*80}\n")
    
    result = parse_sip_pcap(Path(pcap_path))
    
    for call_id, call in result.calls.items():
        print(f"\n📞 Call-ID: {call_id}")
        print(f"   Total messages: {len(call.messages)}")
        
        # Collect all responses
        responses = [msg for msg in call.messages if not msg.is_request]
        print(f"   Response messages: {len(responses)}")
        
        # Find specific responses
        response_183 = None
        response_200_to_carrier = None
        response_200_from_first_dst = None
        
        print(f"\n{'─'*80}")
        print("ALL SIP MESSAGES:")
        print(f"{'─'*80}\n")
        
        for msg in call.messages:
            if msg.is_request:
                prefix = "REQ"
                info = f"{msg.method:6s}"
            else:
                prefix = "RES"
                info = f"{msg.status_code:3d}"
            
            sdp_info = ""
            if msg.has_sdp and msg.media_sections:
                for section in msg.media_sections:
                    if section.media_type == "audio":
                        sdp_info = f" | SDP: audio_port={section.port}, ip={section.connection_ip or 'N/A'}"
                        break
                if not sdp_info:
                    sdp_info = " | SDP: (no audio section)"
            
            print(f"  #{msg.packet_number:4d} | {prefix} | {info} | "
                  f"{msg.src_ip:15s} → {msg.dst_ip:15s}{sdp_info}")
            
            # Track specific responses for analysis
            if not msg.is_request:
                if msg.status_code == 183:
                    response_183 = msg
                if msg.status_code == 200:
                    if msg.dst_ip == "4.184.57.49":
                        response_200_to_carrier = msg
                    # Check if this is from the first INVITE destination
                    first_invite = next((m for m in call.messages if m.is_request and m.method == "INVITE"), None)
                    if first_invite and msg.src_ip == first_invite.dst_ip:
                        response_200_from_first_dst = msg
        
        print(f"\n{'─'*80}")
        print("CORRELATION ANALYSIS:")
        print(f"{'─'*80}\n")
        
        # Check for 183 Session Progress with SDP
        if response_183:
            has_sdp = response_183.has_sdp
            audio_port = None
            if has_sdp and response_183.media_sections:
                for section in response_183.media_sections:
                    if section.media_type == "audio":
                        audio_port = section.port
                        break
            print(f"✓ 183 Session Progress found:")
            print(f"    Packet: #{response_183.packet_number}")
            print(f"    SDP: {has_sdp}")
            print(f"    Audio port: {audio_port if audio_port else 'N/A'}")
            print(f"    From: {response_183.src_ip} → To: {response_183.dst_ip}")
        else:
            print("✗ No 183 Session Progress found")
        
        print()
        
        # Check for 200 OK to carrier (4.184.57.49)
        if response_200_to_carrier:
            has_sdp = response_200_to_carrier.has_sdp
            audio_port = None
            if has_sdp and response_200_to_carrier.media_sections:
                for section in response_200_to_carrier.media_sections:
                    if section.media_type == "audio":
                        audio_port = section.port
                        break
            print(f"✓ 200 OK to carrier (4.184.57.49) found:")
            print(f"    Packet: #{response_200_to_carrier.packet_number}")
            print(f"    SDP: {has_sdp}")
            print(f"    Audio port: {audio_port if audio_port else 'N/A'}")
            print(f"    From: {response_200_to_carrier.src_ip}")
        else:
            print("✗ No 200 OK to carrier (4.184.57.49) found")
        
        print()
        
        # Check for 200 OK from first INVITE destination (10.95.5.198)
        first_invite = next((m for m in call.messages if m.is_request and m.method == "INVITE"), None)
        if first_invite:
            print(f"First INVITE destination: {first_invite.dst_ip}")
            if response_200_from_first_dst:
                has_sdp = response_200_from_first_dst.has_sdp
                audio_port = None
                if has_sdp and response_200_from_first_dst.media_sections:
                    for section in response_200_from_first_dst.media_sections:
                        if section.media_type == "audio":
                            audio_port = section.port
                            break
                print(f"✓ 200 OK from first_invite_dst ({response_200_from_first_dst.src_ip}) found:")
                print(f"    Packet: #{response_200_from_first_dst.packet_number}")
                print(f"    SDP: {has_sdp}")
                print(f"    Audio port: {audio_port if audio_port else 'N/A'}")
                print(f"    To: {response_200_from_first_dst.dst_ip}")
            else:
                print(f"✗ No 200 OK from first_invite_dst ({first_invite.dst_ip}) found")
        
        print(f"\n{'='*80}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python temp_analyze_sip.py <pcap_file>")
        sys.exit(1)
    
    analyze_responses(sys.argv[1])
