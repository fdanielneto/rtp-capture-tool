#!/usr/bin/env python3
"""
Test script for configurable correlation and filters.

Validates that:
1. New dataclasses load correctly
2. YAML parsing works with new structure
3. Correlation config is accessible
4. Filter config is accessible
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.correlation_case_loader import (
    get_loader,
    CorrelationCase,
    CorrelationBehaviorConfig,
    FiltersConfig,
)


def test_basic_loading():
    """Test that cases load with new structure."""
    print("=" * 80)
    print("TEST 1: Basic Case Loading")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    print(f"✓ Loaded {len(cases)} correlation cases")
    
    for case in cases:
        print(f"  - {case.name} (P:{case.priority})")
    
    print()
    return len(cases) > 0


def test_correlation_config():
    """Test that correlation config loads correctly."""
    print("=" * 80)
    print("TEST 2: Correlation Configuration")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    # Check if any case has correlation.config
    cases_with_config = [c for c in cases if c.correlation and c.correlation.config]
    
    print(f"Cases with correlation.config: {len(cases_with_config)}")
    
    for case in cases_with_config:
        config = case.correlation.config
        print(f"\n{case.name}:")
        print(f"  Strategy: {case.correlation.strategy}")
        print(f"  Carrier IP source: {config.carrier_ip_source}")
        print(f"  Core IP source: {config.core_ip_source}")
        print(f"  Response priority: {config.response_priority}")
        print(f"  RTP Engine detection: {config.rtp_engine_detection}")
        print(f"  Enable hop fallback: {config.enable_hop_fallback}")
        print(f"  Block XCC responses: {config.block_xcc_responses}")
    
    print()
    return True


def test_filters_config():
    """Test that filters config loads correctly."""
    print("=" * 80)
    print("TEST 3: Filters Configuration")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    # Check if any case has filters
    cases_with_filters = [c for c in cases if c.filters]
    
    print(f"Cases with filters config: {len(cases_with_filters)}")
    
    for case in cases_with_filters:
        filters = case.filters
        print(f"\n{case.name}:")
        print(f"  Template set: {filters.template_set}")
        print(f"  Use default templates: {filters.use_default_templates}")
        print(f"  Custom templates enabled: {filters.custom_templates_enabled}")
        print(f"  Custom steps: {len(filters.steps)}")
        
        if filters.custom_templates_enabled and filters.steps:
            print(f"\n  Custom filter steps:")
            for step in filters.steps:
                print(f"    Step {step.step}: {step.leg_name} ({step.leg_key})")
                print(f"      Phase1 template: {step.phase1_template[:60]}...")
                print(f"      Phase2 template: {step.phase2_template[:60]}...")
                print(f"      Required fields: {', '.join(step.required_fields)}")
    
    print()
    return True


def test_backward_compatibility():
    """Test that existing cases still work without new config."""
    print("=" * 80)
    print("TEST 4: Backward Compatibility")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    # Cases without new config should still work
    legacy_cases = [c for c in cases if not c.correlation.config and not c.filters]
    
    print(f"Legacy cases (no config/filters): {len(legacy_cases)}")
    
    for case in legacy_cases:
        print(f"  ✓ {case.name} - strategy={case.correlation.strategy}")
        # Make sure basic fields are accessible
        assert case.name
        assert case.description
        assert case.priority >= 0
        assert case.detection
        assert case.correlation
    
    print(f"\n✓ All {len(legacy_cases)} legacy cases loaded successfully")
    print()
    return True


def test_priority_ordering():
    """Test that cases are sorted by priority."""
    print("=" * 80)
    print("TEST 5: Priority Ordering")
    print("=" * 80)
    
    loader = get_loader()
    cases = loader.get_cases()
    
    priorities = [c.priority for c in cases]
    sorted_priorities = sorted(priorities, reverse=True)
    
    if priorities == sorted_priorities:
        print("✓ Cases are correctly sorted by priority (descending)")
        print(f"  Priority range: {max(priorities)} → {min(priorities)}")
    else:
        print("✗ Cases are NOT sorted correctly!")
        print(f"  Actual: {priorities}")
        print(f"  Expected: {sorted_priorities}")
        return False
    
    print()
    return True


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "CORRELATION CONFIG LOADER TESTS" + " " * 27 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    tests = [
        ("Basic Loading", test_basic_loading),
        ("Correlation Config", test_correlation_config),
        ("Filters Config", test_filters_config),
        ("Backward Compatibility", test_backward_compatibility),
        ("Priority Ordering", test_priority_ordering),
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
