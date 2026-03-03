#!/usr/bin/env python3
"""Test script: Reorder RTP packets by sequence number."""
from pathlib import Path
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

def reorder_rtp_by_sequence(input_pcap, output_pcap):
    """Read PCAP, parse RTP, reorder by sequence number."""
    print(f"Reading {input_pcap}...")
    packets = rdpcap(str(input_pcap))
    
    rtp_packets = []
    for pkt in packets:
        if IP in pkt and UDP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            # RTP header: version(2bits) + padding + ...
            if len(payload) >= 12 and (payload[0] >> 6) == 2:
                # Extract RTP sequence number (bytes 2-3)
                seq = int.from_bytes(payload[2:4], byteorder='big')
                rtp_packets.append((seq, pkt))
    
    print(f"Found {len(rtp_packets)} RTP packets")
    
    # Sort by sequence number (handle wrap around)
    rtp_packets.sort(key=lambda x: x[0])
    
    # Write sorted packets
    sorted_packets = [pkt for seq, pkt in rtp_packets]
    wrpcap(str(output_pcap), sorted_packets)
    print(f"Wrote {len(sorted_packets)} packets to {output_pcap}")

if __name__ == "__main__":
    input_file = Path("/tmp/rtp_extracted.pcap")
    output_file = Path("/tmp/rtp_reordered.pcap")
    reorder_rtp_by_sequence(input_file, output_file)
    print("\n✅ Done! Test in Wireshark:")
    print(f"   open -a Wireshark {output_file}")
