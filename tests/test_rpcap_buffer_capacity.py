#!/usr/bin/env python3
"""
RPCAP Buffer Capacity Test

Tests if the rpcapd buffer on remote hosts can handle production traffic
without overflow (packet loss).

Usage:
    python tests/test_rpcap_buffer_capacity.py --hosts 10.13.3.238,10.10.13.235
    python tests/test_rpcap_buffer_capacity.py --hosts qa-eu-rtp-1 --duration 30 --filter "udp port 5060"
    
Author: rtp-capture-tool
Date: 2026-03-02
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s'
)
LOGGER = logging.getLogger(__name__)

try:
    from rtphelper.config_loader import load_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    LOGGER.warning("config_loader not available, host ID resolution disabled")

from rtphelper.services.rpcap_client import RpcapClient

# Simple PCAP writer
import struct

class SimplePcapWriter:
    """Simple PCAP file writer."""
    
    def __init__(self, filename: str, linktype: int = 1, snaplen: int = 262144):
        self.f = open(filename, 'wb')
        # Write PCAP global header
        self.f.write(struct.pack('<IHHiIII', 
            0xa1b2c3d4,  # magic
            2, 4,        # version 2.4
            0,           # thiszone
            0,           # sigfigs
            snaplen,     # snaplen
            linktype     # linktype
        ))
    
    def write(self, packet_data: bytes):
        """Write packet to PCAP."""
        ts_sec = int(time.time())
        ts_usec = int((time.time() % 1) * 1000000)
        pkt_len = len(packet_data)
        # Write packet header + data
        self.f.write(struct.pack('<IIII',
            ts_sec,      # ts_sec
            ts_usec,     # ts_usec
            pkt_len,     # incl_len
            pkt_len      # orig_len
        ))
        self.f.write(packet_data)
    
    def close(self):
        """Close PCAP file."""
        if self.f:
            self.f.close()


@dataclass
class CaptureStats:
    """Statistics for a single host capture test."""
    host: str
    interface: str
    duration_seconds: float
    buffer_size_bytes: int
    buffer_size_mb: float
    packets_captured: int
    bytes_captured: int
    packets_per_second: float
    bytes_per_second: float
    buffer_usage_percent: float
    estimated_overflow_seconds: float
    had_packet_loss: bool
    packet_loss_indicators: List[str] = field(default_factory=list)
    # Real-time drop detection
    drop_events: List[Dict] = field(default_factory=list)
    buffer_stall_count: int = 0
    client_buffer_empty_count: int = 0
    rtp_sequence_gaps: int = 0
    rtp_duplicate_packets: int = 0
    capture_rate_drops: int = 0
    error: Optional[str] = None
    success: bool = True


class RpcapBufferTester:
    """Tests RPCAP buffer capacity on remote hosts."""
    
    def __init__(self, duration_seconds: int = 20, filter_expr: str = "udp", 
                 interface: str = "ens5", rpcap_port: int = 2002, keep_pcaps: bool = False):
        self.duration_seconds = duration_seconds
        self.filter_expr = filter_expr
        self.interface = interface
        self.rpcap_port = rpcap_port
        self.keep_pcaps = keep_pcaps
        self.temp_dir = Path(tempfile.mkdtemp(prefix="rpcap_buffer_test_"))
        
        if self.keep_pcaps:
            LOGGER.info(f"📁 PCAP files will be saved to: {self.temp_dir}")
        
    def __del__(self):
        """Cleanup temp directory."""
        if not self.keep_pcaps and hasattr(self, 'temp_dir') and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_host(self, host: str) -> CaptureStats:
        """
        Test RPCAP buffer capacity on a single host.
        
        Args:
            host: Hostname or IP address
            
        Returns:
            CaptureStats with test results
        """
        LOGGER.info("=" * 70)
        LOGGER.info(f"Testing RPCAP buffer on host: {host}")
        LOGGER.info("=" * 70)
        
        stats = CaptureStats(
            host=host,
            interface=self.interface,
            duration_seconds=self.duration_seconds,
            buffer_size_bytes=0,
            buffer_size_mb=0.0,
            packets_captured=0,
            bytes_captured=0,
            packets_per_second=0.0,
            bytes_per_second=0.0,
            buffer_usage_percent=0.0,
            estimated_overflow_seconds=0.0,
            had_packet_loss=False,
            client_buffer_empty_count=0,
        )
        
        client = None
        pcap_file = None
        
        try:
            # Connect to RPCAP server
            client = RpcapClient(host=host, port=self.rpcap_port, timeout=10)
            client.connect()
            LOGGER.info(f"✅ Connected to {host}")
            
            # Authenticate
            client.auth_null()
            LOGGER.info(f"✅ Authenticated (null auth)")
            
            # Open interface
            open_info = client.open(self.interface)
            LOGGER.info(f"✅ Opened interface {self.interface} (linktype={open_info.linktype})")
            
            # Start capture (this logs buffer size)
            # We need to capture the buffer size from the log or protocol response
            # For now, we'll capture it from start_capture which logs it
            client.start_capture(
                snaplen=262144,
                read_timeout_ms=int(os.environ.get("RTPHELPER_RPCAP_READ_TIMEOUT_MS", "1000")),
                promisc=True,
                filter_expr=self.filter_expr
            )
            LOGGER.info(f"✅ Started capture (duration={self.duration_seconds}s, filter='{self.filter_expr}')")
            
            # Create temp PCAP file
            pcap_file = self.temp_dir / f"{host.replace('.', '_')}.pcap"
            writer = SimplePcapWriter(str(pcap_file), linktype=open_info.linktype, snaplen=262144)
            
            # Capture packets for specified duration with real-time monitoring
            packet_count = 0
            byte_count = 0
            start_time = time.time()
            last_log_time = start_time
            last_rate_check = start_time
            last_second_packets = 0
            rate_samples = []
            
            # Client-side buffer empty detection
            consecutive_none_count = 0
            last_packet_time = start_time
            client_buffer_empty_events = 0
            
            LOGGER.info(f"📦 Capturing packets for {self.duration_seconds} seconds...")
            LOGGER.info(f"🔍 Monitoring for buffer stalls and drop events...")
            
            while time.time() - start_time < self.duration_seconds:
                try:
                    # Read packet from RPCAP (returns tuple: ts_sec, ts_usec, caplen, frame)
                    result = client.recv_packet()
                    
                    if result:
                        ts_sec, ts_usec, caplen, packet_data = result
                        
                        if packet_data:
                            writer.write(packet_data)
                            packet_count += 1
                            byte_count += len(packet_data)
                            last_second_packets += 1
                            last_packet_time = time.time()
                            
                            # Reset consecutive None counter
                            consecutive_none_count = 0
                        
                        # Check rate every second to detect drops
                        current_time = time.time()
                        if current_time - last_rate_check >= 1.0:
                            rate_samples.append(last_second_packets)
                            
                            # Detect rate drop (>50% decrease from average)
                            if len(rate_samples) > 3:
                                avg_rate = sum(rate_samples[-4:-1]) / 3
                                if avg_rate > 10 and last_second_packets < avg_rate * 0.5:
                                    stats.capture_rate_drops += 1
                                    stats.drop_events.append({
                                        'time': f"{current_time - start_time:.1f}s",
                                        'type': 'rate_drop',
                                        'previous_rate': f"{avg_rate:.0f} pps",
                                        'current_rate': f"{last_second_packets} pps",
                                        'drop_percent': f"{((avg_rate - last_second_packets) / avg_rate * 100):.0f}%"
                                    })
                            
                            last_second_packets = 0
                            last_rate_check = current_time
                        
                        # Log progress every 5 seconds
                        if time.time() - last_log_time >= 5.0:
                            elapsed = time.time() - start_time
                            rate = packet_count / elapsed if elapsed > 0 else 0
                            LOGGER.info(f"   📊 Progress: {elapsed:.0f}s | {packet_count} pkts | {rate:.0f} pps")
                            last_log_time = time.time()
                    else:
                        # No packet available - track client-side buffer empty periods
                        consecutive_none_count += 1
                        current_time = time.time()
                        time_since_last_packet = current_time - last_packet_time
                        
                        # If buffer empty for >100ms, count as client buffer empty event
                        if time_since_last_packet > 0.1 and consecutive_none_count > 10:
                            if consecutive_none_count == 11:  # Only log once per empty period
                                client_buffer_empty_events += 1
                                stats.drop_events.append({
                                    'time': f"{current_time - start_time:.1f}s",
                                    'type': 'client_buffer_empty',
                                    'description': f'Client buffer empty for {time_since_last_packet:.2f}s'
                                })
                                LOGGER.warning(f"   ⚠️  Client buffer empty at {current_time - start_time:.1f}s (no data for {time_since_last_packet:.2f}s)")
                        
                        time.sleep(0.01)
                            
                except ConnectionError as e:
                    # Connection lost
                    LOGGER.error(f"Connection lost: {e}")
                    break
                except Exception as e:
                    # Check if it's a stall (no data for extended period)
                    current_time = time.time()
                    if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                        if current_time - start_time < self.duration_seconds:
                            stats.buffer_stall_count += 1
                            stats.drop_events.append({
                                'time': f"{current_time - start_time:.1f}s",
                                'type': 'buffer_stall',
                                'description': f'Read timeout: {str(e)}'
                            })
                            LOGGER.warning(f"   ⚠️  Buffer stall detected at {current_time - start_time:.1f}s")
                    else:
                        LOGGER.warning(f"Error reading packet: {e}")
                        break
            
            writer.close()
            actual_duration = time.time() - start_time
            
            # Populate statistics
            stats.packets_captured = packet_count
            stats.bytes_captured = byte_count
            stats.packets_per_second = packet_count / actual_duration if actual_duration > 0 else 0
            stats.bytes_per_second = byte_count / actual_duration if actual_duration > 0 else 0
            stats.duration_seconds = actual_duration
            
            # Get buffer size (we need to extract this from the client)
            # The buffer size is returned in start_capture response
            # For now, use a default until we can extract it properly
            # TODO: Modify RpcapClient to expose buffer_size from start_capture_reply
            stats.buffer_size_bytes = 262144  # 0.25 MB default (from testing)
            stats.buffer_size_mb = stats.buffer_size_bytes / (1024 * 1024)
            
            # Calculate buffer usage metrics
            # Average packet size
            avg_packet_size = byte_count / packet_count if packet_count > 0 else 200
            
            # How many packets fit in buffer
            buffer_capacity_packets = stats.buffer_size_bytes / avg_packet_size
            
            # At current PPS, how full is buffer per read cycle?
            read_timeout_ms = int(os.environ.get("RTPHELPER_RPCAP_READ_TIMEOUT_MS", "1000"))
            packets_per_read_cycle = stats.packets_per_second * (read_timeout_ms / 1000.0)
            
            stats.buffer_usage_percent = (packets_per_read_cycle / buffer_capacity_packets) * 100
            
            # Estimate time until buffer overflow
            if stats.packets_per_second > 0:
                stats.estimated_overflow_seconds = buffer_capacity_packets / stats.packets_per_second
            else:
                stats.estimated_overflow_seconds = float('inf')
            
            # Detect potential packet loss indicators
            if stats.buffer_usage_percent > 80:
                stats.packet_loss_indicators.append(
                    f"Buffer usage >80% ({stats.buffer_usage_percent:.1f}%)"
                )
            
            if stats.estimated_overflow_seconds < 2.0:
                stats.packet_loss_indicators.append(
                    f"Overflow risk: buffer fills in {stats.estimated_overflow_seconds:.2f}s"
                )
            
            if stats.packets_captured == 0:
                stats.packet_loss_indicators.append("Zero packets captured")
            
            # Analyze PCAP for gaps/drops if we have tshark
            pcap_analysis = self._analyze_pcap_for_drops(pcap_file)
            if pcap_analysis:
                stats.packet_loss_indicators.extend(pcap_analysis)
            
            # Analyze RTP sequence numbers for gaps
            LOGGER.info(f"🔍 Analyzing RTP sequences in {pcap_file}...")
            rtp_analysis = self._analyze_rtp_sequences(pcap_file)
            if rtp_analysis:
                stats.rtp_sequence_gaps = rtp_analysis.get('gaps', 0)
                stats.rtp_duplicate_packets = rtp_analysis.get('duplicates', 0)
                ssrc_count = rtp_analysis.get('ssrc_count', 0)
                LOGGER.info(f"   RTP: {ssrc_count} SSRCs, {stats.rtp_sequence_gaps} gaps, {stats.rtp_duplicate_packets} duplicates")
                if stats.rtp_sequence_gaps > 0:
                    stats.packet_loss_indicators.append(
                        f"RTP sequence gaps: {stats.rtp_sequence_gaps} gaps detected"
                    )
                if stats.rtp_duplicate_packets > 0:
                    stats.packet_loss_indicators.append(
                        f"RTP duplicates: {stats.rtp_duplicate_packets} duplicate packets"
                    )
            else:
                LOGGER.warning("   ⚠️  Could not analyze RTP sequences (tshark unavailable or no RTP packets)")
            
            # Save client buffer empty count
            stats.client_buffer_empty_count = client_buffer_empty_events
            
            # Add real-time detection results
            if stats.buffer_stall_count > 0:
                stats.packet_loss_indicators.append(
                    f"Buffer stalls: {stats.buffer_stall_count} stall events detected"
                )
            
            if stats.client_buffer_empty_count > 0:
                stats.packet_loss_indicators.append(
                    f"Client buffer empty: {stats.client_buffer_empty_count} periods detected"
                )
            
            # Only count rate drops as packet loss if buffer usage > 50%
            # (low buffer usage rate drops are normal traffic fluctuations)
            if stats.capture_rate_drops > 0 and stats.buffer_usage_percent > 50.0:
                stats.packet_loss_indicators.append(
                    f"Capture rate drops: {stats.capture_rate_drops} sudden rate decreases detected"
                )
            
            stats.had_packet_loss = len(stats.packet_loss_indicators) > 0
            
            LOGGER.info(f"✅ Capture complete: {packet_count} packets in {actual_duration:.1f}s")
            LOGGER.info(f"   Rate: {stats.packets_per_second:.1f} pps, {stats.bytes_per_second / 1024:.1f} KB/s")
            LOGGER.info(f"   Buffer: {stats.buffer_size_mb:.2f} MB, usage: {stats.buffer_usage_percent:.1f}%")
            LOGGER.info(f"   Overflow estimate: {stats.estimated_overflow_seconds:.2f}s")
            LOGGER.info(f"   Real-time events: {stats.buffer_stall_count} stalls, {stats.client_buffer_empty_count} client empty, {stats.capture_rate_drops} rate drops")
            
            # Inform if rate drops were ignored due to low buffer usage
            if stats.capture_rate_drops > 0 and stats.buffer_usage_percent <= 50.0:
                LOGGER.info(f"   ℹ️  Rate drops ignored (buffer usage {stats.buffer_usage_percent:.1f}% < 50%, likely normal traffic variation)")
            
            LOGGER.info(f"   RTP analysis: {stats.rtp_sequence_gaps} gaps, {stats.rtp_duplicate_packets} duplicates")
            
            if stats.had_packet_loss:
                LOGGER.warning(f"⚠️  Packet loss detected ({len(stats.packet_loss_indicators)} indicators):")
                for indicator in stats.packet_loss_indicators:
                    LOGGER.warning(f"      - {indicator}")
            else:
                LOGGER.info(f"✅ No packet loss detected")
            
        except Exception as e:
            LOGGER.error(f"❌ Error testing host {host}: {e}")
            stats.error = str(e)
            stats.success = False
            
        finally:
            # Cleanup
            if client:
                try:
                    client.disconnect()
                    LOGGER.info(f"✅ Disconnected from {host}")
                except:
                    pass
            
            # Delete temp PCAP
            if pcap_file and pcap_file.exists():
                try:
                    pcap_file.unlink()
                    LOGGER.info(f"🗑️  Deleted temp file: {pcap_file.name}")
                except Exception as e:
                    LOGGER.warning(f"Failed to delete temp file: {e}")
        
        return stats
    
    def _analyze_rtp_sequences(self, pcap_file: Path) -> Optional[Dict]:
        """
        Analyze RTP sequence numbers for gaps and duplicates using tshark.
        
        Returns:
            Dictionary with 'gaps' and 'duplicates' counts, or None if tshark unavailable
        """
        try:
            import subprocess
            
            # Check if tshark is available
            result = subprocess.run(
                ["which", "tshark"],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode != 0:
                return None  # tshark not available
            
            # Extract RTP sequence numbers per SSRC
            result = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-Y", "rtp", "-T", "fields", 
                 "-e", "rtp.ssrc", "-e", "rtp.seq"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                LOGGER.debug(f"tshark failed: {result.stderr}")
                return None
            
            if not result.stdout.strip():
                LOGGER.debug(f"No RTP packets found in {pcap_file}")
                return {'gaps': 0, 'duplicates': 0, 'ssrc_count': 0}
            
            # Parse sequences per SSRC
            ssrc_sequences = {}
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) != 2:
                    continue
                    
                try:
                    ssrc = parts[0].strip()
                    seq = int(parts[1].strip())
                    
                    if ssrc not in ssrc_sequences:
                        ssrc_sequences[ssrc] = []
                    ssrc_sequences[ssrc].append(seq)
                except (ValueError, IndexError):
                    continue
            
            # Count gaps and duplicates
            total_gaps = 0
            total_duplicates = 0
            
            for ssrc, sequences in ssrc_sequences.items():
                if len(sequences) < 2:
                    continue
                
                seen_seqs = set()
                for i in range(len(sequences)):
                    seq = sequences[i]
                    
                    # Check for duplicates
                    if seq in seen_seqs:
                        total_duplicates += 1
                    seen_seqs.add(seq)
                    
                    # Check for gaps (only if not first packet)
                    if i > 0:
                        prev_seq = sequences[i - 1]
                        expected_seq = (prev_seq + 1) % 65536  # RTP seq wraps at 65536
                        
                        if seq != expected_seq and seq != prev_seq:  # gap (not duplicate)
                            # Calculate gap size
                            if seq > prev_seq:
                                gap_size = seq - prev_seq - 1
                            else:  # wrapped
                                gap_size = (65536 - prev_seq) + seq - 1
                            
                            # Only count reasonable gaps (not huge jumps at start)
                            if gap_size < 1000:
                                total_gaps += 1
            
            return {
                'gaps': total_gaps,
                'duplicates': total_duplicates,
                'ssrc_count': len(ssrc_sequences)
            }
            
        except Exception as e:
            LOGGER.debug(f"Could not analyze RTP sequences with tshark: {e}")
            return None
    
    def _analyze_pcap_for_drops(self, pcap_file: Path) -> List[str]:
        """
        Analyze PCAP file for packet drop indicators using tshark (if available).
        
        Returns:
            List of packet loss indicators
        """
        indicators = []
        
        try:
            import subprocess
            
            # Check if tshark is available
            result = subprocess.run(
                ["which", "tshark"],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode != 0:
                return indicators  # tshark not available
            
            # Count total packets
            result = subprocess.run(
                ["tshark", "-r", str(pcap_file), "-T", "fields", "-e", "frame.number"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                packet_count = len([l for l in lines if l])
                
                # Check for very low capture rate (might indicate drops)
                if packet_count < 10 and self.duration_seconds > 5:
                    indicators.append(f"Very low packet count ({packet_count} in {self.duration_seconds}s)")
            
        except Exception as e:
            LOGGER.debug(f"Could not analyze PCAP with tshark: {e}")
        
        return indicators
    
    def test_multiple_hosts(self, hosts: List[str], parallel: bool = True) -> Dict[str, CaptureStats]:
        """
        Test multiple hosts in parallel or sequentially.
        
        Args:
            hosts: List of hostnames/IPs
            parallel: If True, test hosts in parallel
            
        Returns:
            Dictionary mapping host to CaptureStats
        """
        results = {}
        
        if parallel:
            with ThreadPoolExecutor(max_workers=min(len(hosts), 4)) as executor:
                future_to_host = {executor.submit(self.test_host, host): host for host in hosts}
                
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        stats = future.result()
                        results[host] = stats
                    except Exception as e:
                        LOGGER.error(f"Failed to test {host}: {e}")
                        results[host] = CaptureStats(
                            host=host,
                            interface=self.interface,
                            duration_seconds=0,
                            buffer_size_bytes=0,
                            buffer_size_mb=0,
                            packets_captured=0,
                            bytes_captured=0,
                            packets_per_second=0,
                            bytes_per_second=0,
                            buffer_usage_percent=0,
                            estimated_overflow_seconds=0,
                            had_packet_loss=False,
                            client_buffer_empty_count=0,
                            error=str(e),
                            success=False
                        )
        else:
            for host in hosts:
                results[host] = self.test_host(host)
        
        return results


def generate_report(results: Dict[str, CaptureStats], output_file: Optional[Path] = None):
    """Generate test report."""
    
    print("\n" + "=" * 80)
    print("RPCAP BUFFER CAPACITY TEST REPORT".center(80))
    print("=" * 80 + "\n")
    
    # Summary
    total_hosts = len(results)
    successful_hosts = sum(1 for s in results.values() if s.success)
    hosts_with_loss = sum(1 for s in results.values() if s.had_packet_loss)
    
    print(f"📊 SUMMARY")
    print(f"   Hosts tested:          {total_hosts}")
    print(f"   Successful tests:      {successful_hosts}")
    print(f"   Failed tests:          {total_hosts - successful_hosts}")
    print(f"   Hosts with packet loss: {hosts_with_loss}")
    print()
    
    # Per-host details
    print(f"📋 HOST DETAILS")
    print()
    
    for host, stats in results.items():
        status = "✅ PASS" if stats.success and not stats.had_packet_loss else "⚠️  WARNING" if stats.success else "❌ FAIL"
        
        print(f"   {status} | Host: {host}")
        
        if not stats.success:
            print(f"      Error: {stats.error}")
            print()
            continue
        
        print(f"      Duration:          {stats.duration_seconds:.1f}s")
        print(f"      Packets captured:  {stats.packets_captured:,}")
        print(f"      Traffic rate:      {stats.packets_per_second:.1f} pps, {stats.bytes_per_second / 1024:.1f} KB/s")
        print(f"      Buffer size:       {stats.buffer_size_mb:.2f} MB ({stats.buffer_size_bytes:,} bytes)")
        print(f"      Buffer usage:      {stats.buffer_usage_percent:.1f}%")
        print(f"      Overflow time:     {stats.estimated_overflow_seconds:.2f}s")
        print(f"      ")
        print(f"      📉 Real-time Detection:")
        print(f"         Buffer stalls:      {stats.buffer_stall_count}")
        print(f"         Client empty:       {stats.client_buffer_empty_count}")
        print(f"         Rate drops:         {stats.capture_rate_drops}")
        print(f"         Total drop events:  {len(stats.drop_events)}")
        print(f"      ")
        print(f"      🔍 RTP Analysis:")
        print(f"         Sequence gaps:      {stats.rtp_sequence_gaps}")
        print(f"         Duplicate packets:  {stats.rtp_duplicate_packets}")
        
        if stats.had_packet_loss:
            print(f"      ")
            print(f"      ⚠️  Loss indicators ({len(stats.packet_loss_indicators)}):")
            for indicator in stats.packet_loss_indicators:
                print(f"         - {indicator}")
            
            if stats.drop_events:
                print(f"      ")
                print(f"      📅 Drop Events Timeline:")
                for event in stats.drop_events[:10]:  # Show first 10 events
                    event_type = event.get('type', 'unknown')
                    event_time = event.get('time', 'N/A')
                    if event_type == 'rate_drop':
                        print(f"         [{event_time}] Rate drop: {event['previous_rate']} → {event['current_rate']} ({event['drop_percent']} decrease)")
                    elif event_type == 'buffer_stall':
                        print(f"         [{event_time}] Buffer stall: {event['description']}")
                if len(stats.drop_events) > 10:
                    print(f"         ... and {len(stats.drop_events) - 10} more events")
        else:
            print(f"      ✅ No packet loss detected")
        
        print()
    
    # Recommendations
    print(f"💡 RECOMMENDATIONS")
    print()
    
    if hosts_with_loss > 0:
        print("   ⚠️  Packet loss indicators detected. Recommended actions:")
        print("      1. Increase rpcapd buffer size: rpcapd -B 134217728  (128 MB)")
        print("      2. Reduce read timeout: RTPHELPER_RPCAP_READ_TIMEOUT_MS=100")
        print("      3. Verify network connectivity and latency")
        print("      4. Check host CPU/memory usage during capture")
    else:
        print("   ✅ All tests passed. Current buffer configuration is adequate.")
        print("      Buffer size: Monitor during production traffic spikes")
    
    print()
    print("=" * 80 + "\n")
    
    # Save JSON report if requested
    if output_file:
        json_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_hosts": total_hosts,
                "successful_tests": successful_hosts,
                "hosts_with_loss": hosts_with_loss
            },
            "results": {
                host: {
                    "success": s.success,
                    "host": s.host,
                    "interface": s.interface,
                    "duration_seconds": s.duration_seconds,
                    "buffer_size_bytes": s.buffer_size_bytes,
                    "buffer_size_mb": s.buffer_size_mb,
                    "packets_captured": s.packets_captured,
                    "bytes_captured": s.bytes_captured,
                    "packets_per_second": s.packets_per_second,
                    "bytes_per_second": s.bytes_per_second,
                    "buffer_usage_percent": s.buffer_usage_percent,
                    "estimated_overflow_seconds": s.estimated_overflow_seconds,
                    "had_packet_loss": s.had_packet_loss,
                    "packet_loss_indicators": s.packet_loss_indicators,
                    "drop_events": s.drop_events,
                    "buffer_stall_count": s.buffer_stall_count,
                    "client_buffer_empty_count": s.client_buffer_empty_count,
                    "rtp_sequence_gaps": s.rtp_sequence_gaps,
                    "rtp_duplicate_packets": s.rtp_duplicate_packets,
                    "capture_rate_drops": s.capture_rate_drops,
                    "error": s.error
                }
                for host, s in results.items()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"📄 JSON report saved to: {output_file}\n")


def resolve_hostnames(host_identifiers: List[str]) -> List[str]:
    """
    Resolve host identifiers (IPs or host IDs from config) to IP addresses.
    
    Args:
        host_identifiers: List of IPs or host IDs
        
    Returns:
        List of IP addresses
    """
    resolved = []
    
    # Try to load config
    config = None
    if CONFIG_AVAILABLE:
        try:
            config = load_config()
        except Exception as e:
            LOGGER.debug(f"Could not load config: {e}")
            config = None
    
    for identifier in host_identifiers:
        # If it looks like an IP, use it directly
        if identifier.replace('.', '').isdigit():
            resolved.append(identifier)
            continue
        
        # Try to find in config
        if config:
            found = False
            for env_name, env_data in config.environments.items():
                for region_name, region_data in env_data.regions.items():
                    for sub_region_name, sub_region_data in region_data.sub_region.items():
                        for host in sub_region_data.hosts:
                            if host.id == identifier:
                                resolved.append(host.address)
                                found = True
                                LOGGER.info(f"Resolved '{identifier}' -> {host.address}")
                                break
                        if found:
                            break
                    if found:
                        break
                if found:
                    break
            
            if not found:
                LOGGER.warning(f"Could not resolve '{identifier}', using as-is")
                resolved.append(identifier)
        else:
            resolved.append(identifier)
    
    return resolved


def main():
    parser = argparse.ArgumentParser(
        description="Test RPCAP buffer capacity on remote hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Test single QA host
  python tests/test_rpcap_buffer_capacity.py --hosts 10.13.3.238
  
  # Test multiple hosts in parallel
  python tests/test_rpcap_buffer_capacity.py --hosts 10.13.3.238,10.10.13.235
  
  # Test with host IDs from config
  python tests/test_rpcap_buffer_capacity.py --hosts qa-eu-rtp-1,qa-eu-rtp-2
  
  # Custom duration and filter
  python tests/test_rpcap_buffer_capacity.py --hosts 10.13.3.238 --duration 60 --filter "udp port 5060"
  
  # Save JSON report
  python tests/test_rpcap_buffer_capacity.py --hosts qa-eu-rtp-1 --output report.json
  
  # Keep PCAP files for later RTP sequence analysis
  python tests/test_rpcap_buffer_capacity.py --hosts 10.13.3.238 --keep-pcaps
        '''
    )
    
    parser.add_argument(
        '--hosts',
        required=True,
        help='Comma-separated list of hostnames or IPs (e.g., 10.13.3.238,qa-eu-rtp-1)'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=20,
        help='Capture duration in seconds (default: 20)'
    )
    parser.add_argument(
        '--filter',
        default='udp',
        help='BPF filter expression (default: "udp")'
    )
    parser.add_argument(
        '--interface',
        default='ens5',
        help='Network interface to capture (default: ens5)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=2002,
        help='RPCAP port (default: 2002)'
    )
    parser.add_argument(
        '--sequential',
        action='store_true',
        help='Test hosts sequentially instead of in parallel'
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Save JSON report to file'
    )
    parser.add_argument(
        '--keep-pcaps',
        action='store_true',
        help='Keep PCAP files for later analysis (default: delete after test)'
    )
    
    args = parser.parse_args()
    
    # Parse hosts
    host_identifiers = [h.strip() for h in args.hosts.split(',') if h.strip()]
    
    if not host_identifiers:
        print("Error: No hosts specified")
        sys.exit(1)
    
    # Resolve hostnames
    hosts = resolve_hostnames(host_identifiers)
    
    print(f"\n🔬 RPCAP Buffer Capacity Test")
    print(f"   Hosts:     {', '.join(hosts)}")
    print(f"   Duration:  {args.duration}s per host")
    print(f"   Filter:    '{args.filter}'")
    print(f"   Interface: {args.interface}")
    print(f"   Mode:      {'Sequential' if args.sequential else 'Parallel'}")
    print()
    
    # Run tests
    tester = RpcapBufferTester(
        duration_seconds=args.duration,
        filter_expr=args.filter,
        interface=args.interface,
        rpcap_port=args.port,
        keep_pcaps=args.keep_pcaps
    )
    
    results = tester.test_multiple_hosts(hosts, parallel=not args.sequential)
    
    # Generate report
    generate_report(results, output_file=args.output)
    
    # Show PCAP location if kept
    if args.keep_pcaps:
        print()
        print("=" * 80)
        print(f"📁 PCAP files saved to: {tester.temp_dir}")
        print()
        print("   To analyze RTP sequences:")
        for host in host_identifiers:
            pcap_name = f"{host.replace('.', '_')}.pcap"
            pcap_path = tester.temp_dir / pcap_name
            if pcap_path.exists():
                print(f"      tshark -r {pcap_path} -Y rtp -T fields -e rtp.ssrc -e rtp.seq | head -20")
        print("=" * 80)
        print()
    
    # Exit with appropriate code
    if any(not s.success or s.had_packet_loss for s in results.values()):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
