#!/usr/bin/env python3
"""Quick validation script for configurable correlation."""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from rtphelper.services.correlation_case_loader import (
        get_loader,
        CorrelationBehaviorConfig,
        FiltersConfig,
        FilterStepTemplate,
    )
    
    print("✓ Imports successful")
    
    # Try to load cases
    loader = get_loader()
    cases = loader.get_cases()
    
    print(f"✓ Loaded {len(cases)} cases")
    
    # Find test case
    test_case = None
    for case in cases:
        if case.name == "test_configurable_case":
            test_case = case
            break
    
    if test_case:
        print(f"✓ Found test case: {test_case.name}")
        
        # Validate correlation config
        if test_case.correlation and test_case.correlation.config:
            config = test_case.correlation.config
            print(f"✓ Correlation config loaded:")
            print(f"  - carrier_ip_source: {config.carrier_ip_source}")
            print(f"  - core_ip_source: {config.core_ip_source}")
            print(f"  - response_priority: {config.response_priority}")
            print(f"  - rtp_engine_detection: {config.rtp_engine_detection}")
        else:
            print("✗ No correlation config found!")
            sys.exit(1)
        
        # Validate filters config
        if test_case.filters:
            filters = test_case.filters
            print(f"✓ Filters config loaded:")
            print(f"  - template_set: {filters.template_set}")
            print(f"  - custom_templates_enabled: {filters.custom_templates_enabled}")
            print(f"  - steps: {len(filters.steps)}")
            
            if filters.steps:
                step = filters.steps[0]
                print(f"  - First step: {step.leg_name} (step {step.step})")
                print(f"    phase1: {step.phase1_template}")
                print(f"    phase2: {step.phase2_template}")
        else:
            print("✗ No filters config found!")
            sys.exit(1)
        
        print("\n✓ ALL VALIDATIONS PASSED")
        
    else:
        print("✗ Test case not found (might be disabled)")
        # Check all cases
        print("\nAvailable cases:")
        for c in cases:
            status = "disabled" if not c.enabled else "enabled"
            print(f"  - {c.name} ({status})")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
