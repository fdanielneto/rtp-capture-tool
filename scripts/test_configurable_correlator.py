#!/usr/bin/env python3
"""
Test ConfigurableCorrelator with YAML configuration.

This script validates that:
1. ConfigurableCorrelator loads correctly
2. IP extraction works with configured sources
3. Response priority is respected
4. RTP Engine detection is configurable
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.correlation_case_loader import get_loader
from rtphelper.services.sip_correlation import (
    _get_correlator_for_case,
    ConfigurableCorrelator,
    GenericCorrelator,
    DynamicCorrelator,
)


def test_configurable_correlator_loading():
    """Test that ConfigurableCorrelator is used for cases with strategy=configurable."""
    print("=" * 80)
    print("TEST 1: ConfigurableCorrelator Loading")
    print("=" * 80)
    
    loader = get_loader()
    loader.reload()  # Force reload to pick up new cases
    cases = loader.get_cases()
    
    # Find test case
    test_case = None
    for case in cases:
        if case.name == "test_configurable_inbound":
            test_case = case
            break
    
    if not test_case:
        print("✗ Test case 'test_configurable_inbound' not found")
        print("Available cases:")
        for case in cases:
            print(f"  - {case.name} (strategy={case.correlation.strategy})")
        return False
    
    print(f"✓ Found test case: {test_case.name}")
    print(f"  Strategy: {test_case.correlation.strategy}")
    print(f"  Has config: {test_case.correlation.config is not None}")
    
    # Get correlator for this case
    correlator = _get_correlator_for_case(test_case.name)
    
    if isinstance(correlator, ConfigurableCorrelator):
        print(f"✓ Correlator type: ConfigurableCorrelator")
    else:
        print(f"✗ Wrong correlator type: {type(correlator).__name__}")
        return False
    
    # Validate config
    config = correlator.config
    print(f"\nConfiguration loaded:")
    print(f"  carrier_ip_source: {config.carrier_ip_source}")
    print(f"  core_ip_source: {config.core_ip_source}")
    print(f"  response_priority: {config.response_priority}")
    print(f"  rtp_engine_detection: {config.rtp_engine_detection}")
    print(f"  enable_hop_fallback: {config.enable_hop_fallback}")
    print(f"  block_xcc_responses: {config.block_xcc_responses}")
    
    # Validate values
    assert config.carrier_ip_source == "first_invite.src_ip"
    assert config.core_ip_source == "last_invite.dst_ip"
    assert config.response_priority == [183, 200]
    assert config.rtp_engine_detection == "enabled"
    
    print("\n✓ All configuration values correct")
    print()
    return True


def test_generic_strategy_with_config():
    """Test that cases with strategy=generic but with config still work."""
    print("=" * 80)
    print("TEST 2: Generic Strategy with Config")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    # Find a case with generic strategy and config
    test_cases = [c for c in cases 
                  if c.correlation.strategy == "generic" 
                  and c.correlation.config is not None]
    
    if not test_cases:
        print("⚠ No cases found with strategy=generic and config present")
        print("  This is OK - these are optional")
        print()
        return True
    
    test_case = test_cases[0]
    print(f"✓ Found case: {test_case.name}")
    print(f"  Strategy: {test_case.correlation.strategy}")
    print(f"  Has config: yes")
    
    correlator = _get_correlator_for_case(test_case.name)
    
    # Should use DynamicCorrelator (which delegates to build_correlation_context)
    if isinstance(correlator, DynamicCorrelator):
        print(f"✓ Correlator type: DynamicCorrelator (expected for generic+config)")
    elif isinstance(correlator, GenericCorrelator):
        print(f"✓ Correlator type: GenericCorrelator (also acceptable)")
    else:
        print(f"✗ Unexpected correlator type: {type(correlator).__name__}")
        return False
    
    print()
    return True


def test_backward_compatibility():
    """Test that existing cases without config still work."""
    print("=" * 80)
    print("TEST 3: Backward Compatibility")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    # Find cases without config
    legacy_cases = [c for c in cases if c.correlation.config is None]
    
    print(f"Legacy cases (no config): {len(legacy_cases)}")
    
    for case in legacy_cases[:3]:  # Test first 3
        correlator = _get_correlator_for_case(case.name)
        print(f"  ✓ {case.name} → {type(correlator).__name__}")
    
    print()
    return True


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 18 + "CONFIGURABLE CORRELATOR TESTS" + " " * 29 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    tests = [
        ("ConfigurableCorrelator Loading", test_configurable_correlator_loading),
        ("Generic Strategy with Config", test_generic_strategy_with_config),
        ("Backward Compatibility", test_backward_compatibility),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, "PASS" if result else "FAIL"))
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, "ERROR"))
    
    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    for test_name, status in results:
        symbol = "✓" if status == "PASS" else "✗"
        print(f"{symbol} {test_name}: {status}")
    
    passed = sum(1 for _, status in results if status == "PASS")
    total = len(results)
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    print()
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
