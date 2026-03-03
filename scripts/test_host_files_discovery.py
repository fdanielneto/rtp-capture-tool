#!/usr/bin/env python3
"""
Test script to diagnose raw files discovery issues.
Tests the _refresh_session_host_files logic with sample data.
"""
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.capture_service import CaptureSession


def test_host_files_discovery():
    """Test the host files discovery logic"""
    print("=" * 80)
    print("Testing Host Files Discovery Logic")
    print("=" * 80)
    
    # Check if any e2e-tests directories exist with actual captures
    e2e_dir = Path(__file__).parent.parent / "e2e-tests"
    
    if not e2e_dir.exists():
        print(f"\n❌ e2e-tests directory not found: {e2e_dir}")
        return
    
    print(f"\n📂 Scanning e2e-tests directory: {e2e_dir}\n")
    
    # Find all raw/ directories
    raw_dirs = list(e2e_dir.glob("*/*/raw"))
    
    if not raw_dirs:
        print("❌ No raw/ directories found in e2e-tests")
        return
    
    print(f"✅ Found {len(raw_dirs)} raw/ directories\n")
    
    for raw_dir in raw_dirs:
        print("-" * 80)
        print(f"Testing: {raw_dir.relative_to(e2e_dir.parent)}")
        print("-" * 80)
        
        # Find all .pcap and .pcapng files
        pcap_files = list(raw_dir.glob("*.pcap")) + list(raw_dir.glob("*.pcapng"))
        
        if not pcap_files:
            print("  ⚠️  No .pcap/.pcapng files found in this directory")
            continue
        
        print(f"  Found {len(pcap_files)} capture files:")
        for f in pcap_files:
            print(f"    - {f.name} ({f.stat().st_size:,} bytes)")
        
        # Extract host IDs from filenames
        # Filename format: <sub_region>-<host_id>-<interface>-<sequence>.pcap
        # Example: voip-rtpengine01-em1-0001.pcap
        discovered_hosts = set()
        for f in pcap_files:
            parts = f.stem.split('-')
            if len(parts) >= 4:
                # parts[0] = sub_region, parts[1] = host_id
                host_id = parts[1]
                discovered_hosts.add(host_id)
        
        print(f"\n  📋 Discovered host IDs from filenames: {sorted(discovered_hosts)}")
        
        # Simulate the _refresh_session_host_files logic
        print("\n  🔍 Simulating _refresh_session_host_files logic:")
        print("  " + "=" * 76)
        
        # Test Case 1: With host_packet_counts populated (normal case)
        print("\n  Test 1: With host_packet_counts populated (normal flow)")
        host_packet_counts = {host_id: 0 for host_id in discovered_hosts}
        refreshed_files = {}
        
        for host_id in host_packet_counts.keys():
            files = sorted(raw_dir.glob(f"*-{host_id}-*.pcap"))
            if not files:
                files = sorted(raw_dir.glob(f"*-{host_id}-*.pcapng"))
            refreshed_files[host_id] = files
            print(f"    {host_id}: {len(files)} files")
        
        total_files_test1 = sum(len(files) for files in refreshed_files.values())
        if total_files_test1 > 0:
            print(f"  ✅ SUCCESS: Would find {total_files_test1} files")
        else:
            print(f"  ❌ FAIL: No files found")
        
        # Test Case 2: With empty host_packet_counts (fallback discovery)
        print("\n  Test 2: With empty host_packet_counts (fallback discovery)")
        host_packet_counts_empty = {}
        
        # Discover from filenames
        all_files = list(raw_dir.glob("*.pcap")) + list(raw_dir.glob("*.pcapng"))
        discovered_hosts_fallback = set()
        for f in all_files:
            parts = f.stem.split('-')
            if len(parts) >= 4:
                host_id = parts[1]
                discovered_hosts_fallback.add(host_id)
        
        print(f"    Fallback discovered hosts: {sorted(discovered_hosts_fallback)}")
        
        refreshed_files_fallback = {}
        for host_id in discovered_hosts_fallback:
            files = sorted(raw_dir.glob(f"*-{host_id}-*.pcap"))
            if not files:
                files = sorted(raw_dir.glob(f"*-{host_id}-*.pcapng"))
            refreshed_files_fallback[host_id] = files
            print(f"    {host_id}: {len(files)} files")
        
        total_files_test2 = sum(len(files) for files in refreshed_files_fallback.values())
        if total_files_test2 > 0:
            print(f"  ✅ SUCCESS: Would find {total_files_test2} files via fallback")
        else:
            print(f"  ❌ FAIL: No files found via fallback")
        
        # Test Case 3: Check if pattern matching works correctly
        print("\n  Test 3: Pattern matching validation")
        test_patterns = [
            (f"*-{list(discovered_hosts)[0]}-*.pcap", "Current pattern"),
            (f"{list(discovered_hosts)[0]}-*.pcap", "Without leading wildcard"),
            (f"*{list(discovered_hosts)[0]}*.pcap", "With wildcards both sides"),
        ] if discovered_hosts else []
        
        for pattern, desc in test_patterns:
            matches = list(raw_dir.glob(pattern))
            print(f"    Pattern: {pattern:40s} → {len(matches)} matches ({desc})")
        
        print()


def check_actual_session_state():
    """Check if there's an active capture service with sessions"""
    print("\n" + "=" * 80)
    print("Checking for Active Capture Sessions")
    print("=" * 80)
    
    try:
        # Try to import and check capture service state
        from rtphelper.web.app import CAPTURE_SERVICE
        
        if CAPTURE_SERVICE is None:
            print("⚠️  CAPTURE_SERVICE is None")
            return
        
        # Check active session
        if hasattr(CAPTURE_SERVICE, '_active_session'):
            session = CAPTURE_SERVICE._active_session
            if session:
                print(f"✅ Active session found: {session.session_id}")
                print(f"   Running: {session.running}")
                print(f"   Raw dir: {session.raw_dir}")
                print(f"   Host packet counts: {len(session.host_packet_counts)} hosts")
                print(f"   Host files: {len(session.host_files)} hosts")
                for host_id, files in session.host_files.items():
                    print(f"      {host_id}: {len(files)} files")
            else:
                print("⚠️  No active session")
        
        # Check sessions registry
        if hasattr(CAPTURE_SERVICE, '_sessions'):
            sessions = CAPTURE_SERVICE._sessions
            print(f"\n📋 Total sessions in registry: {len(sessions)}")
            for session_id, session in list(sessions.items())[-5:]:  # Last 5
                print(f"   {session_id}:")
                print(f"      Running: {session.running}")
                print(f"      Host files: {len(session.host_files)} hosts")
                for host_id, files in session.host_files.items():
                    print(f"         {host_id}: {len(files)} files")
    
    except ImportError as e:
        print(f"⚠️  Cannot import CAPTURE_SERVICE: {e}")
    except Exception as e:
        print(f"❌ Error checking session state: {e}")


if __name__ == "__main__":
    print("\n🔬 RTP Capture Tool - Host Files Discovery Diagnostic\n")
    test_host_files_discovery()
    check_actual_session_state()
    print("\n" + "=" * 80)
    print("Diagnostic Complete")
    print("=" * 80 + "\n")
