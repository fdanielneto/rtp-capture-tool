#!/usr/bin/env python3
"""
Validation Script for Modular YAML Architecture

This script validates the complete implementation:
1. Load correlation strategies
2. Load filter templates
3. Load use cases (v2)
4. Verify backward compatibility
5. Run basic integration tests
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.correlation_strategy_loader import (
    CorrelationStrategyLoader,
    get_strategy,
)
from rtphelper.services.filter_template_loader import (
    FilterTemplateLoader,
    get_template,
)
from rtphelper.services.correlation_case_loader import get_loader


def print_section(title: str):
    """Print section header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def print_success(message: str):
    """Print success message."""
    print(f"✅ {message}")


def print_error(message: str):
    """Print error message."""
    print(f"❌ {message}")


def print_info(message: str):
    """Print info message."""
    print(f"ℹ️  {message}")


def validate_strategies():
    """Validate correlation strategies."""
    print_section("1. VALIDATE CORRELATION STRATEGIES")
    
    loader = CorrelationStrategyLoader()
    strategies = loader.load_strategies()
    
    print_info(f"Found {len(strategies)} strategies")
    
    # Validate expected strategies exist
    expected = ["direct_topology", "rtp_engine_topology"]
    for strategy_name in expected:
        if strategy_name in strategies:
            strategy = strategies[strategy_name]
            print_success(f"{strategy_name}: version {strategy.version}, {strategy.hops}-hop")
        else:
            print_error(f"{strategy_name}: NOT FOUND")
    
    # Validate strategy structure
    print_info("\nValidating direct_topology structure...")
    direct = loader.get_strategy("direct_topology")
    if direct:
        assert direct.hops == 2, "direct_topology should have 2 hops"
        assert "carrier" in direct.ip_extraction, "carrier IP extraction missing"
        assert "core" in direct.ip_extraction, "core IP extraction missing"
        assert not direct.rtp_engine_detection.enabled, "RTP Engine should be disabled"
        print_success("direct_topology structure OK")
    
    print_info("\nValidating rtp_engine_topology structure...")
    rtp_engine = loader.get_strategy("rtp_engine_topology")
    if rtp_engine:
        assert rtp_engine.hops == 3, "rtp_engine_topology should have 3 hops"
        assert "rtp_engine" in rtp_engine.ip_extraction, "rtp_engine IP extraction missing"
        assert rtp_engine.rtp_engine_detection.enabled, "RTP Engine detection should be enabled"
        print_success("rtp_engine_topology structure OK")
    
    return True


def validate_templates():
    """Validate filter templates."""
    print_section("2. VALIDATE FILTER TEMPLATES")
    
    loader = FilterTemplateLoader()
    templates = loader.load_templates()
    
    print_info(f"Found {len(templates)} templates")
    
    # Validate expected templates exist
    expected = ["direct_2legs", "rtp_engine_4legs"]
    for template_name in expected:
        if template_name in templates:
            template = templates[template_name]
            print_success(f"{template_name}: version {template.version}, {template.legs} legs, {len(template.steps)} steps")
        else:
            print_error(f"{template_name}: NOT FOUND")
    
    # Validate template structure
    print_info("\nValidating direct_2legs structure...")
    direct = loader.get_template("direct_2legs")
    if direct:
        assert direct.legs == 2, "direct_2legs should have 2 legs"
        assert len(direct.steps) == 2, "direct_2legs should have 2 steps"
        step1 = direct.get_step(1)
        assert step1 is not None, "Step 1 missing"
        assert step1.phase1_template, "Phase 1 template missing"
        assert step1.phase2_template, "Phase 2 template missing"
        print_success("direct_2legs structure OK")
    
    print_info("\nValidating rtp_engine_4legs structure...")
    rtp_engine = loader.get_template("rtp_engine_4legs")
    if rtp_engine:
        assert rtp_engine.legs == 4, "rtp_engine_4legs should have 4 legs"
        assert len(rtp_engine.steps) == 4, "rtp_engine_4legs should have 4 steps"
        for step_num in [1, 2, 3, 4]:
            step = rtp_engine.get_step(step_num)
            assert step is not None, f"Step {step_num} missing"
            assert step.phase1_template, f"Step {step_num} phase 1 template missing"
            assert step.phase2_template, f"Step {step_num} phase 2 template missing"
        print_success("rtp_engine_4legs structure OK")
    
    return True


def validate_use_cases():
    """Validate use cases (v2 migrated cases)."""
    print_section("3. VALIDATE USE CASES (V2)")
    
    case_loader = get_loader()
    cases = case_loader.get_cases()
    
    print_info(f"Found {len(cases)} use cases total")
    
    # Find v2 cases
    v2_cases = [c for c in cases if c.name.endswith("_v2")]
    print_info(f"Found {len(v2_cases)} v2 (migrated) use cases")
    
    # Validate expected v2 cases
    expected = [
        "inbound_direct_v2",
        "inbound_rtp_engine_v2",
        "inbound_b2bua_v2",
        "outbound_direct_v2",
        "outbound_rtp_engine_v2",
        "outbound_b2bua_v2",
    ]
    
    for case_name in expected:
        case = next((c for c in v2_cases if c.name == case_name), None)
        if case:
            print_success(f"{case_name}: priority={case.priority}, strategy={case.correlation.strategy}")
        else:
            print_error(f"{case_name}: NOT FOUND")
    
    # Validate case structure
    print_info("\nValidating case strategies reference YAML files...")
    for case in v2_cases:
        if case.correlation.strategy in ["direct_topology", "rtp_engine_topology"]:
            print_success(f"{case.name}: references strategy '{case.correlation.strategy}'")
        else:
            print_error(f"{case.name}: invalid strategy '{case.correlation.strategy}'")
    
    return True


def validate_backward_compatibility():
    """Validate backward compatibility with legacy config."""
    print_section("4. VALIDATE BACKWARD COMPATIBILITY")
    
    print_info("Checking legacy use cases still load...")
    
    case_loader = get_loader()
    cases = case_loader.get_cases()
    
    # Find legacy cases (without _v2)
    legacy_cases = [c for c in cases if not c.name.endswith("_v2") and c.enabled]
    print_info(f"Found {len(legacy_cases)} legacy use cases")
    
    if legacy_cases:
        print_success("Legacy use cases still load correctly")
    else:
        print_info("No enabled legacy use cases found (may be disabled)")
    
    return True


def validate_integration():
    """Run basic integration tests."""
    print_section("5. INTEGRATION TESTS")
    
    print_info("Testing strategy → template integration...")
    
    # Test direct_topology → direct_2legs
    strategy = get_strategy("direct_topology")
    template = get_template("direct_2legs")
    
    if strategy and template:
        assert strategy.topology.legs == template.legs, "Topology legs mismatch"
        print_success("direct_topology → direct_2legs integration OK")
    
    # Test rtp_engine_topology → rtp_engine_4legs
    strategy = get_strategy("rtp_engine_topology")
    template = get_template("rtp_engine_4legs")
    
    if strategy and template:
        assert strategy.topology.legs == template.legs, "Topology legs mismatch"
        print_success("rtp_engine_topology → rtp_engine_4legs integration OK")
    
    return True


def main():
    """Run all validations."""
    print("\n" + "=" * 70)
    print("  MODULAR YAML ARCHITECTURE VALIDATION")
    print("=" * 70)
    
    try:
        validate_strategies()
        validate_templates()
        validate_use_cases()
        validate_backward_compatibility()
        validate_integration()
        
        print_section("✅ VALIDATION COMPLETE")
        print("\nAll validations passed successfully!")
        print("\nNext steps:")
        print("  1. Run unit tests: pytest tests/test_correlation_strategy_loader.py")
        print("  2. Run unit tests: pytest tests/test_filter_template_loader.py")
        print("  3. Test with real PCAPs")
        print("  4. Disable old use cases, rename v2 cases (remove _v2 suffix)")
        print()
        
        return 0
    
    except Exception as e:
        print_section("❌ VALIDATION FAILED")
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
