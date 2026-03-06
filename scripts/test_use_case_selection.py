#!/usr/bin/env python3
"""
Test script to validate use case selection with different scenarios.

This script simulates different call scenarios and shows which use case would be selected.
Useful for testing the priority and multi_call_id validation without needing real pcaps.

Usage:
    python scripts/test_use_case_selection.py
"""

import sys
from pathlib import Path

# Add rtphelper to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.sip_parser import SipCall, SipMessage
from rtphelper.services.sip_correlation import identify_use_case, _matches_case
from rtphelper.services.correlation_case_loader import CorrelationCaseLoader


def create_mock_call(call_id: str = "test@test") -> SipCall:
    """Create a minimal mock SipCall for testing."""
    call = SipCall(call_id=call_id)
    
    # Add a minimal INVITE message
    invite = SipMessage(
        packet_number=1,
        ts=0.0,
        src_ip="10.1.1.1",
        dst_ip="10.2.2.2",
        proto="UDP",
        is_request=True
    )
    invite.method = "INVITE"
    invite.call_id = call_id
    invite.headers = {}
    call.messages.append(invite)
    
    return call


def test_scenario(
    scenario_name: str,
    direction: str,
    num_call_ids: int,
    expected_use_case: str = None
):
    """
    Test a specific scenario and show which use case is selected.
    
    Args:
        scenario_name: Description of the scenario
        direction: inbound or outbound
        num_call_ids: Number of Call-IDs in the group
        expected_use_case: Expected use case name (optional)
    """
    print("\n" + "=" * 80)
    print(f"SCENARIO: {scenario_name}")
    print("=" * 80)
    print(f"Direction: {direction}")
    print(f"Call-IDs: {num_call_ids}")
    print()
    
    # Create mock call
    mock_call = create_mock_call()
    
    # Identify use case
    use_case = identify_use_case(mock_call, direction, num_call_ids=num_call_ids)
    
    print(f"Selected Use Case: {use_case}")
    
    # Load case details
    loader = CorrelationCaseLoader()
    cases = {c.name: c for c in loader.get_cases()}
    
    if use_case in cases:
        case = cases[use_case]
        print(f"  Priority: {case.priority}")
        print(f"  Strategy: {case.correlation.strategy}")
        print(f"  multi_call_id: {case.correlation.multi_call_id}")
        print(f"  Description: {case.description}")
    
    # Check if expected
    if expected_use_case:
        if use_case == expected_use_case:
            print(f"\n✅ PASS: Got expected use case '{expected_use_case}'")
        else:
            print(f"\n❌ FAIL: Expected '{expected_use_case}', got '{use_case}'")
            return False
    
    # Show top 5 evaluated cases
    print("\nTop 5 evaluated cases:")
    for i, case in enumerate(loader.get_cases()[:5], 1):
        matches = _matches_case(mock_call, direction, case, num_call_ids=num_call_ids)
        status = "✅" if matches else "❌"
        print(f"  {i}. {status} {case.name} (priority={case.priority}, multi_call_id={case.correlation.multi_call_id})")
    
    return True


def main():
    """Run test scenarios."""
    print("=" * 80)
    print("USE CASE SELECTION TEST SUITE")
    print("=" * 80)
    print()
    print("Testing different scenarios to validate use case selection logic")
    print("with priorities and multi_call_id validation.")
    
    results = []
    
    # Scenario 1: Inbound with 1 Call-ID (should select specific case, not direct as last resort)
    results.append(test_scenario(
        "Inbound with 1 Call-ID",
        direction="inbound",
        num_call_ids=1,
        expected_use_case=None  # Will depend on which case matches first
    ))
    
    # Scenario 2: Inbound with 2 Call-IDs (should skip multi_call_id=false cases)
    results.append(test_scenario(
        "Inbound with 2 Call-IDs (multiple)",
        direction="inbound",
        num_call_ids=2,
        expected_use_case=None  # Should NOT be inbound_direct_v2 or inbound_rtp_engine_v2
    ))
    
    # Scenario 3: Outbound with 1 Call-ID
    results.append(test_scenario(
        "Outbound with 1 Call-ID",
        direction="outbound",
        num_call_ids=1,
        expected_use_case=None
    ))
    
    # Scenario 4: Outbound with 2 Call-IDs
    results.append(test_scenario(
        "Outbound with 2 Call-IDs (multiple)",
        direction="outbound",
        num_call_ids=2,
        expected_use_case=None
    ))
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    # Show v2 cases priorities
    print("\nV2 Use Cases Priorities:")
    loader = CorrelationCaseLoader()
    v2_cases = [(c.name, c.priority, c.correlation.multi_call_id) 
                for c in loader.get_cases() if c.name.endswith("_v2")]
    v2_cases.sort(key=lambda x: x[1], reverse=True)
    
    for name, priority, multi_call_id in v2_cases:
        print(f"  {priority:3d} - {name:30s} (multi_call_id={multi_call_id})")
    
    print("\nExpected behavior:")
    print("  - Specific cases (b2bua, rtp_engine) have higher priority than generic (direct)")
    print("  - multi_call_id=false cases should be skipped when num_call_ids > 1")
    print("  - multi_call_id=true cases should be skipped when num_call_ids == 1")
    
    passed = sum(results)
    total = len(results)
    print(f"\nTests: {passed}/{total} passed")
    
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
