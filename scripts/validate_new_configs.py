#!/usr/bin/env python3
"""
Quick validation script for the 6 new correlation configuration files.

Validates:
- YAML syntax correctness
- Required fields present
- ConfigurableCorrelator compatibility
- Template configuration
- Multi Call-ID grouping settings
- RTP Engine detection settings
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

print("\n" + "="*70)
print("NEW CORRELATION CONFIGS VALIDATION")
print("="*70)

# Test new configuration files
new_configs = [
    "inbound_no_xcc.yaml",
    "inbound_xcc.yaml",
    "inbound_2cid.yaml",
    "outbound_no_xcc.yaml",
    "outbound_xcc.yaml",
    "outbound_2cid.yaml",
]

tests_passed = 0
tests_failed = 0

def validate_config(filename):
    """Validate a single configuration file"""
    global tests_passed, tests_failed
    
    try:
        from rtphelper.services.correlation_case_loader import get_loader
        
        loader = get_loader()
        cases = loader.load_cases()
        
        # Find the specific case
        case = None
        for c in cases:
            if c.yaml_file and c.yaml_file.endswith(filename):
                case = c
                break
        
        if not case:
            print(f"✗ FAIL: {filename} - Not loaded by correlation case loader")
            tests_failed += 1
            return False
        
        # Validate required fields
        checks = []
        
        # Check name matches expected pattern
        expected_name = filename.replace(".yaml", "")
        checks.append(("Name matches", case.name == expected_name, f"{case.name} == {expected_name}"))
        
        # Check strategy is configurable
        checks.append(("Strategy", case.correlation_strategy == "configurable", f"strategy={case.correlation_strategy}"))
        
        # Check correlation config exists
        checks.append(("Config exists", case.correlation_config is not None, "correlation_config present"))
        
        if case.correlation_config:
            # Check RTP Engine detection setting
            rtp_detection = case.correlation_config.rtp_engine_detection
            checks.append(("RTP detection set", rtp_detection is not None, f"rtp_engine_detection={rtp_detection}"))
            
            # Check multi Call-ID grouping
            multi_cid = case.correlation_config.group_multi_call_ids
            checks.append(("Multi-CID set", multi_cid is not None, f"group_multi_call_ids={multi_cid}"))
        
        # Check filters config
        checks.append(("Filters exist", case.filters is not None, "filters config present"))
        
        if case.filters:
            # Check template set
            template_set = case.filters.template_set
            checks.append(("Template set", template_set is not None, f"template_set={template_set}"))
        
        # Print results
        all_passed = all(passed for _, passed, _ in checks)
        
        if all_passed:
            print(f"✓ PASS: {filename}")
            tests_passed += 1
            return True
        else:
            print(f"✗ FAIL: {filename}")
            for check_name, passed, detail in checks:
                status = "✓" if passed else "✗"
                print(f"  {status} {check_name}: {detail}")
            tests_failed += 1
            return False
            
    except Exception as e:
        print(f"✗ ERROR: {filename}")
        print(f"  Exception: {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1
        return False


def validate_config_matrix():
    """Validate the configuration matrix"""
    from rtphelper.services.correlation_case_loader import get_loader
    
    loader = get_loader()
    cases = loader.load_cases()
    
    # Build matrix
    matrix = {}
    for filename in new_configs:
        for case in cases:
            if case.yaml_file and case.yaml_file.endswith(filename):
                direction = "inbound" if "inbound" in filename else "outbound"
                has_xcc = "_xcc" in filename or "_2cid" in filename
                has_2cid = "_2cid" in filename
                
                matrix[filename] = {
                    "case": case,
                    "direction": direction,
                    "has_xcc": has_xcc,
                    "has_2cid": has_2cid,
                    "rtp_detection": case.correlation_config.rtp_engine_detection if case.correlation_config else None,
                    "multi_cid": case.correlation_config.group_multi_call_ids if case.correlation_config else None,
                    "template_set": case.filters.template_set if case.filters else None,
                }
                break
    
    # Print matrix
    print("\n" + "="*70)
    print("CONFIGURATION MATRIX")
    print("="*70)
    print(f"{'Config':<25} {'Dir':<10} {'RTP':<10} {'Multi-CID':<12} {'Template':<20}")
    print("-"*70)
    
    for filename, info in sorted(matrix.items()):
        case = info['case']
        rtp = info['rtp_detection'] or "disabled"
        multi = str(info['multi_cid']) if info['multi_cid'] is not None else "false"
        template = info['template_set'] or "direct_topology"
        
        print(f"{case.name:<25} {info['direction']:<10} {rtp:<10} {multi:<12} {template:<20}")
    
    # Validate expected combinations
    print("\n" + "="*70)
    print("EXPECTED COMBINATIONS")
    print("="*70)
    
    expected = [
        ("inbound_no_xcc.yaml", "inbound", "disabled", False, "direct_topology"),
        ("inbound_xcc.yaml", "inbound", "enabled", False, "rtp_engine_topology"),
        ("inbound_2cid.yaml", "inbound", "enabled", True, "rtp_engine_topology"),
        ("outbound_no_xcc.yaml", "outbound", "disabled", False, "direct_topology"),
        ("outbound_xcc.yaml", "outbound", "enabled", False, "rtp_engine_topology"),
        ("outbound_2cid.yaml", "outbound", "enabled", True, "rtp_engine_topology"),
    ]
    
    all_correct = True
    for filename, exp_dir, exp_rtp, exp_multi, exp_template in expected:
        if filename in matrix:
            info = matrix[filename]
            checks = [
                info['direction'] == exp_dir,
                info['rtp_detection'] == exp_rtp,
                info['multi_cid'] == exp_multi,
                info['template_set'] == exp_template,
            ]
            
            if all(checks):
                print(f"✓ {filename:<25} matches expected configuration")
            else:
                print(f"✗ {filename:<25} MISMATCH")
                print(f"  Expected: dir={exp_dir}, rtp={exp_rtp}, multi_cid={exp_multi}, template={exp_template}")
                print(f"  Actual:   dir={info['direction']}, rtp={info['rtp_detection']}, multi_cid={info['multi_cid']}, template={info['template_set']}")
                all_correct = False
        else:
            print(f"✗ {filename:<25} NOT FOUND")
            all_correct = False
    
    return all_correct


def main():
    """Run validation"""
    print("\nValidating new correlation configuration files...\n")
    
    # Validate each file
    print("="*70)
    print("FILE VALIDATION")
    print("="*70)
    for filename in new_configs:
        validate_config(filename)
    
    # Validate configuration matrix
    matrix_ok = validate_config_matrix()
    
    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    print(f"Files validated:  {len(new_configs)}")
    print(f"Passed:           {tests_passed} ({'✓' if tests_passed == len(new_configs) else '✗'})")
    print(f"Failed:           {tests_failed}")
    print(f"Matrix correct:   {'✓' if matrix_ok else '✗'}")
    
    if tests_failed == 0 and matrix_ok:
        print("\n🎉 ALL NEW CONFIGS VALIDATED!")
        print("\nNew configuration files created:")
        for filename in new_configs:
            print(f"  ✓ rtphelper/correlation_cases/{filename}")
        print("\nReady for use with ConfigurableCorrelator!")
        return 0
    else:
        print(f"\n⚠️  {tests_failed} FILE(S) FAILED OR MATRIX INCORRECT")
        return 1


if __name__ == "__main__":
    sys.exit(main())
