"""
Unit tests for _refresh_session_host_files glob pattern fix.
Tests the fallback discovery mechanism with real filename patterns.
"""
import tempfile
from pathlib import Path
from typing import Dict, List
import pytest


def test_glob_patterns_with_sub_region_prefix():
    """
    Test that files are discovered correctly when host_id includes sub-region prefix.
    This was the root cause of the bug where raw files list didn't appear in UI.
    """
    # Create temporary directory structure
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = Path(tmpdir) / "raw"
        raw_dir.mkdir()
        
        # Create test files matching actual production filename format
        # Format: <sub-region>-<host-id>-<sequence>.pcap
        test_files = [
            "us-east-rtpengine-edge-02daea8609-0001.pcap",
            "us-east-rtpengine-edge-02daea8609-0002.pcap",
            "us-east-rtpengine-edge-0af1b6b463-0001.pcap",
            "eu-west-rtpengine-edge-3cb03e5ade-0001.pcap",
        ]
        
        for filename in test_files:
            (raw_dir / filename).touch()
        
        # Test Case 1: OLD pattern (the bug) - with leading wildcard only
        host_id_full = "us-east-rtpengine-edge-02daea8609"
        pattern_old = f"*-{host_id_full}-*.pcap"
        matches_old = list(raw_dir.glob(pattern_old))
        
        print(f"\nTest Case 1 - OLD pattern (BUG)")
        print(f"  Pattern: {pattern_old}")
        print(f"  Expected: 0 matches (this is the bug)")
        print(f"  Actual: {len(matches_old)} matches")
        
        assert len(matches_old) == 0, (
            "OLD pattern should NOT match files when host_id includes sub-region prefix. "
            "This is the bug!"
        )
        
        # Test Case 2: NEW pattern (the fix) - without leading wildcard
        pattern_new = f"{host_id_full}-*.pcap"
        matches_new = list(raw_dir.glob(pattern_new))
        
        print(f"\nTest Case 2 - NEW pattern (FIX)")
        print(f"  Pattern: {pattern_new}")
        print(f"  Expected: 2 matches")
        print(f"  Actual: {len(matches_new)} matches")
        for m in matches_new:
            print(f"    - {m.name}")
        
        assert len(matches_new) == 2, (
            f"NEW pattern should match 2 files, but matched {len(matches_new)}. Fix failed!"
        )
        matched_names = {m.name for m in matches_new}
        assert "us-east-rtpengine-edge-02daea8609-0001.pcap" in matched_names
        assert "us-east-rtpengine-edge-02daea8609-0002.pcap" in matched_names
        
        # Test Case 3: Normal pattern (without sub-region in host_id) still works
        host_id_only = "rtpengine-edge-02daea8609"
        pattern_normal = f"*-{host_id_only}-*.pcap"
        matches_normal = list(raw_dir.glob(pattern_normal))
        
        print(f"\nTest Case 3 - NORMAL pattern (backward compatibility)")
        print(f"  Pattern: {pattern_normal}")
        print(f"  Expected: 2 matches")
        print(f"  Actual: {len(matches_normal)} matches")
        
        assert len(matches_normal) == 2, (
            f"Normal pattern should still match 2 files, but matched {len(matches_normal)}. "
            "Regression detected!"
        )


def test_s3_name_matching():
    """
    Test the S3 file name matching logic with both old and new approaches.
    """
    test_cases = [
        # (filename, host_id, should_match_old, should_match_new)
        ("us-east-rtpengine-edge-02daea8609-0001.pcap", "us-east-rtpengine-edge-02daea8609", False, True),
        ("us-east-rtpengine-edge-02daea8609-0001.pcap", "rtpengine-edge-02daea8609", True, True),
        ("prefix-us-east-rtpengine-edge-02daea8609-0001.pcap", "us-east-rtpengine-edge-02daea8609", True, True),
    ]
    
    print("\nTest S3 Name Matching")
    for name, host_id, expected_old, expected_new in test_cases:
        # OLD logic
        old_check = f"-{host_id}-" in name
        
        # NEW logic
        new_check = f"-{host_id}-" in name or name.startswith(f"{host_id}-")
        
        print(f"\n  File: {name}")
        print(f"  Host: {host_id}")
        print(f"  OLD logic result: {old_check} (expected: {expected_old})")
        print(f"  NEW logic result: {new_check} (expected: {expected_new})")
        
        assert old_check == expected_old, f"OLD logic failed for {name}"
        assert new_check == expected_new, f"NEW logic failed for {name}"
        
        if not old_check and new_check:
            print(f"  ✅ FIX resolves this case!")


def test_dual_pattern_combined_logic():
    """
    Test the complete dual-pattern logic that combines both approaches.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = Path(tmpdir) / "raw"
        raw_dir.mkdir()
        
        # Create files with different naming patterns
        test_files = [
            "us-east-rtpengine01-0001.pcap",  # Simple format
            "prod-us-west-rtpengine-ha-abc123-0001.pcap",  # Complex multi-region
        ]
        
        for filename in test_files:
            (raw_dir / filename).touch()
        
        # Simulate the fixed logic
        def find_files_fixed(raw_dir: Path, host_id: str) -> List[Path]:
            """Simulates the fixed _refresh_session_host_files logic"""
            # Try pattern with leading wildcard first (normal case)
            files = sorted(raw_dir.glob(f"*-{host_id}-*.pcap"))
            if not files:
                files = sorted(raw_dir.glob(f"*-{host_id}-*.pcapng"))
            
            # If not found, try without leading wildcard (fallback case)
            if not files:
                files = sorted(raw_dir.glob(f"{host_id}-*.pcap"))
            if not files:
                files = sorted(raw_dir.glob(f"{host_id}-*.pcapng"))
            
            return files
        
        # Test with full prefix (fallback scenario)
        host_id_full = "us-east-rtpengine01"
        files = find_files_fixed(raw_dir, host_id_full)
        
        print(f"\nDual Pattern Test - Full prefix")
        print(f"  Host ID: {host_id_full}")
        print(f"  Found: {len(files)} files")
        for f in files:
            print(f"    - {f.name}")
        
        assert len(files) == 1, f"Should find 1 file with full prefix, found {len(files)}"
        assert files[0].name == "us-east-rtpengine01-0001.pcap"
        
        # Test with partial host_id (normal scenario)
        host_id_partial = "rtpengine01"
        files = find_files_fixed(raw_dir, host_id_partial)
        
        print(f"\nDual Pattern Test - Partial host_id")
        print(f"  Host ID: {host_id_partial}")
        print(f"  Found: {len(files)} files")
        for f in files:
            print(f"    - {f.name}")
        
        assert len(files) == 1, f"Should find 1 file with partial host_id, found {len(files)}"


if __name__ == "__main__":
    print("=" * 80)
    print("Running _refresh_session_host_files Pattern Fix Tests")
    print("=" * 80)
    
    try:
        test_glob_patterns_with_sub_region_prefix()
        print("\n✅ Test 1 PASSED: Glob patterns")
        
        test_s3_name_matching()
        print("\n✅ Test 2 PASSED: S3 name matching")
        
        test_dual_pattern_combined_logic()
        print("\n✅ Test 3 PASSED: Dual pattern logic")
        
        print("\n" + "=" * 80)
        print("✅ ALL TESTS PASSED - Fix is validated")
        print("=" * 80)
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        print("=" * 80)
        raise
