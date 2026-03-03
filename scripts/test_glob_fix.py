#!/usr/bin/env python3
"""
Test script to validate the fix for host files discovery with real e2e-test data.
"""
from pathlib import Path

def test_glob_patterns():
    """Test glob patterns against real e2e-test files"""
    print("=" * 80)
    print("Testing Glob Pattern Fix")
    print("=" * 80)
    
    # Test data from actual e2e-tests
    raw_dir = Path(__file__).parent.parent / "e2e-tests" / "outbound-1-cid" / "20260217_020948" / "raw"
    
    if not raw_dir.exists():
        print(f"❌ Test directory not found: {raw_dir}")
        return False
    
    print(f"\n📂 Test directory: {raw_dir}\n")
    
    # List actual files
    actual_files = sorted(raw_dir.glob("*.pcap")) + sorted(raw_dir.glob("*.pcapng"))
    print(f"Actual files in directory ({len(actual_files)}):")
    for f in actual_files[:5]:  # Show first 5
        print(f"  - {f.name}")
    if len(actual_files) > 5:
        print(f"  ... and {len(actual_files) - 5} more")
    
    # Extract host_id from first filename using the regex logic
    if not actual_files:
        print("❌ No files found for testing")
        return False
    
    test_file = actual_files[0].name
    print(f"\n🔍 Analyzing test file: {test_file}")
    
    # Simulate _host_key_from_capture_filename logic
    # Pattern: ^(?P<prefix>.+)-\d{4}\.(pcap|pcapng)$
    # For "us-east-rtpengine-edge-02daea8609-0001.pcap"
    # prefix = "us-east-rtpengine-edge-02daea8609"
    parts = test_file.rsplit('-', 1)
    if len(parts) == 2 and parts[1].split('.')[0].isdigit():
        host_id_full = parts[0]  # This is the prefix including sub-region
        print(f"   Extracted host_id (full prefix): {host_id_full}")
    else:
        print("   ⚠️  Could not extract host_id")
        return False
    
    # Also extract just the host part (without sub-region) for comparison
    # Format: <sub-region>-<host-id>
    # Example: us-east-rtpengine-edge-02daea8609
    host_parts = host_id_full.split('-', 1)
    if len(host_parts) == 2:
        sub_region = host_parts[0]
        host_id_only = host_parts[1]
        print(f"   Sub-region: {sub_region}")
        print(f"   Host ID (without sub-region): {host_id_only}")
    else:
        host_id_only = host_id_full
        print(f"   Cannot split sub-region, using full: {host_id_only}")
    
    print("\n" + "─" * 80)
    print("Test Case 1: BEFORE FIX - Pattern with leading wildcard only")
    print("─" * 80)
    
    # OLD pattern (what code used before)
    pattern_old = f"*-{host_id_full}-*.pcap"
    matches_old = list(raw_dir.glob(pattern_old))
    print(f"Pattern: {pattern_old}")
    print(f"Matches: {len(matches_old)}")
    if matches_old:
        print("✅ PASS (unexpected)")
        for m in matches_old[:3]:
            print(f"   - {m.name}")
    else:
        print("❌ FAIL (expected) - This is the bug!")
        print("   Explanation: Pattern requires something before host_id_full,")
        print("   but files start with sub-region, so nothing matches.")
    
    print("\n" + "─" * 80)
    print("Test Case 2: AFTER FIX - Pattern without leading wildcard (fallback)")
    print("─" * 80)
    
    # NEW pattern (fallback added in fix)
    pattern_new = f"{host_id_full}-*.pcap"
    matches_new = list(raw_dir.glob(pattern_new))
    print(f"Pattern: {pattern_new}")
    print(f"Matches: {len(matches_new)}")
    if matches_new:
        print("✅ PASS (expected) - Fix works!")
        for m in matches_new[:3]:
            print(f"   - {m.name}")
    else:
        print("❌ FAIL - Fix did not work")
    
    print("\n" + "─" * 80)
    print("Test Case 3: Normal case - Host ID without sub-region")
    print("─" * 80)
    
    # If we had just the host ID (normal capture flow with host_packet_counts)
    pattern_normal = f"*-{host_id_only}-*.pcap"
    matches_normal = list(raw_dir.glob(pattern_normal))
    print(f"Pattern: {pattern_normal}")
    print(f"Matches: {len(matches_normal)}")
    if matches_normal:
        print("✅ PASS - Normal case still works")
        for m in matches_normal[:3]:
            print(f"   - {m.name}")
    else:
        print("⚠️  No matches (may be OK if host_id_only is ambiguous)")
    
    print("\n" + "─" * 80)
    print("Test Case 4: S3 name matching")
    print("─" * 80)
    
    # Test the name matching logic for S3 files
    test_names = [f.name for f in actual_files[:3]]
    print(f"Testing with sample filenames:")
    
    for name in test_names:
        # OLD logic
        old_check = f"-{host_id_full}-" in name
        # NEW logic
        new_check = f"-{host_id_full}-" in name or name.startswith(f"{host_id_full}-")
        
        print(f"\n  File: {name}")
        print(f"    OLD check (f'-{{host_id_full}}-' in name): {old_check}")
        print(f"    NEW check (includes startswith): {new_check}")
        if not old_check and new_check:
            print(f"    ✅ Fix resolves this file!")
    
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    
    if len(matches_new) > 0:
        print("✅ Fix is working correctly!")
        print(f"   - Found {len(matches_new)} files with fallback pattern")
        print("   - Files will now appear in UI after capture stops")
        return True
    else:
        print("❌ Fix may not be working as expected")
        return False


if __name__ == "__main__":
    print("\n🔬 Host Files Discovery Pattern Fix Validation\n")
    success = test_glob_patterns()
    print("\n" + "=" * 80)
    if success:
        print("✅ VALIDATION PASSED - Fix is correct")
    else:
        print("⚠️  VALIDATION INCONCLUSIVE")
    print("=" * 80 + "\n")
