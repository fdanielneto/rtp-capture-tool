#!/usr/bin/env python3
"""
Test script for dynamic correlation case loading.

This script tests:
1. Loading cases from YAML files
2. Case detection based on SIP headers
3. Dynamic correlator instantiation
4. Adding new cases without code changes
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rtphelper.services.correlation_case_loader import get_loader, reload_cases
from rtphelper.services.sip_correlation import identify_use_case, _get_correlator_for_case


def print_separator(title: str):
    """Print section separator."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_case_loading():
    """Test loading cases from YAML files."""
    print_separator("TEST 1: Load Correlation Cases from YAML")
    
    loader = get_loader()
    cases = loader.get_cases()
    
    print(f"\nLoaded {len(cases)} correlation cases:")
    print(f"Cases directory: {loader.cases_dir}")
    print()
    
    for case in cases:
        print(f"  • {case.name}")
        print(f"    Priority: {case.priority}")
        print(f"    Direction: {case.detection.direction}")
        print(f"    Description: {case.description}")
        print(f"    Strategy: {case.correlation.strategy}")
        if case.detection.headers:
            print(f"    Headers: {[h.pattern for h in case.detection.headers]}")
        print()
    
    assert len(cases) > 0, "No cases loaded!"
    print("✅ PASS: Cases loaded successfully")


def test_case_priority():
    """Test that cases are sorted by priority."""
    print_separator("TEST 2: Case Priority Ordering")
    
    loader = get_loader()
    cases = loader.get_cases()
    
    priorities = [case.priority for case in cases]
    is_sorted = all(priorities[i] >= priorities[i+1] for i in range(len(priorities)-1))
    
    print(f"\nCase priorities: {priorities}")
    print(f"Correctly sorted (descending): {is_sorted}")
    
    assert is_sorted, "Cases not sorted by priority!"
    print("✅ PASS: Cases properly prioritized")


def test_use_case_detection():
    """Test use case detection with mock SIP call."""
    print_separator("TEST 3: Use Case Detection")
    
    # Create mock SIP call classes
    from dataclasses import dataclass, field
    from typing import List
    
    @dataclass
    class MockSipMessage:
        is_request: bool = True
        method: str = "INVITE"
        headers: List[str] = field(default_factory=list)
    
    @dataclass
    class MockSipCall:
        call_id: str = "test-123"
        messages: List[MockSipMessage] = field(default_factory=list)
    
    # Test 1: Inbound with Diversion header
    print("\n  Test Case A: Inbound INVITE with Diversion header")
    call1 = MockSipCall(messages=[
        MockSipMessage(headers=["Diversion: <sip:+1234567890@carrier.com>"])
    ])
    use_case1 = identify_use_case(call1, "inbound")
    print(f"    Detected use case: {use_case1}")
    assert use_case1 == "inbound_pstn_carrier", f"Expected 'inbound_pstn_carrier', got '{use_case1}'"
    print("    ✅ Correct")
    
    # Test 2: Outbound without special headers
    print("\n  Test Case B: Outbound INVITE without special headers")
    call2 = MockSipCall(messages=[
        MockSipMessage(headers=["From: <sip:user@core.example.com>"])
    ])
    use_case2 = identify_use_case(call2, "outbound")
    print(f"    Detected use case: {use_case2}")
    # Should match outbound_pstn_carrier (priority 40) or generic_outbound (priority 10)
    assert use_case2 in ["outbound_pstn_carrier", "generic_outbound"], f"Unexpected use case: {use_case2}"
    print("    ✅ Correct")
    
    # Test 3: Inbound with P-Asserted-Identity
    print("\n  Test Case C: Inbound INVITE with P-Asserted-Identity")
    call3 = MockSipCall(messages=[
        MockSipMessage(headers=["P-Asserted-Identity: <sip:+9876543210@trunk.com>"])
    ])
    use_case3 = identify_use_case(call3, "inbound")
    print(f"    Detected use case: {use_case3}")
    assert use_case3 == "inbound_pstn_carrier", f"Expected 'inbound_pstn_carrier', got '{use_case3}'"
    print("    ✅ Correct")
    
    print("\n✅ PASS: Use case detection working")


def test_dynamic_correlator():
    """Test dynamic correlator instantiation."""
    print_separator("TEST 4: Dynamic Correlator Creation")
    
    print("\n  Testing correlator retrieval:")
    
    # Test existing hardcoded case
    correlator1 = _get_correlator_for_case("inbound_pstn_carrier")
    print(f"    • inbound_pstn_carrier: {type(correlator1).__name__}")
    
    # Test dynamic case
    correlator2 = _get_correlator_for_case("generic_inbound")
    print(f"    • generic_inbound: {type(correlator2).__name__}")
    
    # Test unknown case
    correlator3 = _get_correlator_for_case("unknown")
    print(f"    • unknown: {type(correlator3).__name__}")
    
    print("\n✅ PASS: Correlators instantiated successfully")


def test_reload_cases():
    """Test reloading cases."""
    print_separator("TEST 5: Reload Cases")
    
    loader = get_loader()
    cases_before = len(loader.get_cases())
    print(f"\n  Cases before reload: {cases_before}")
    
    cases_after = reload_cases()
    print(f"  Cases after reload: {len(cases_after)}")
    
    assert len(cases_after) == cases_before, "Case count changed after reload"
    print("\n✅ PASS: Reload working correctly")


def test_case_file_format():
    """Test that all YAML files follow correct format."""
    print_separator("TEST 6: YAML File Format Validation")
    
    loader = get_loader()
    cases = loader.get_cases()
    
    print("\n  Validating case configurations:")
    
    required_fields = ["name", "description", "detection", "correlation"]
    required_detection = ["direction"]
    required_correlation = ["strategy"]
    
    all_valid = True
    for case in cases:
        errors = []
        
        # Check detection fields
        if not case.detection.direction:
            errors.append("Missing detection.direction")
        elif case.detection.direction not in ["inbound", "outbound", "both"]:
            errors.append(f"Invalid direction: {case.detection.direction}")
        
        # Check correlation fields
        if not case.correlation.strategy:
            errors.append("Missing correlation.strategy")
        
        if errors:
            print(f"    ❌ {case.name}: {', '.join(errors)}")
            all_valid = False
        else:
            print(f"    ✅ {case.name}")
    
    assert all_valid, "Some YAML files have invalid format"
    print("\n✅ PASS: All YAML files valid")


def main():
    """Run all tests."""
    print("\n" + "█" * 70)
    print("  DYNAMIC CORRELATION CASE LOADING - TEST SUITE")
    print("█" * 70)
    
    try:
        test_case_loading()
        test_case_priority()
        test_use_case_detection()
        test_dynamic_correlator()
        test_reload_cases()
        test_case_file_format()
        
        print("\n" + "="*70)
        print("  🎉 ALL TESTS PASSED!")
        print("="*70)
        print("\nThe dynamic correlation case system is working correctly.")
        print("\nTo add a new use case:")
        print("  1. Create a new .yaml file in rtphelper/correlation_cases/")
        print("  2. Define detection rules and correlation strategy")
        print("  3. Restart the application or call reload_cases()")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
