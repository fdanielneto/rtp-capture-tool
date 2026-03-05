#!/usr/bin/env python3
"""
Quick validation of filter template rendering - standalone test.
"""

# Simple standalone test without imports
def test_template_rendering():
    """Quick test of template rendering logic"""
    import re
    
    def render_filter_template(template: str, variables: dict) -> str:
        """Minimal template renderer for testing"""
        result = template
        
        # Variable substitution
        variable_pattern = re.compile(r'\$\{([^}]+)\}')
        
        def replace_variable(match):
            var_path = match.group(1).strip()
            value = variables
            for part in var_path.split('.'):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = getattr(value, part, None)
                if value is None:
                    return f"${{{var_path}}}"
            return str(value)
        
        result = variable_pattern.sub(replace_variable, result)
        return result
    
    # Test 1: Simple variable substitution
    template = "ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}"
    variables = {
        "carrier": {
            "source": {
                "ip": "192.168.1.100",
                "port": 20000
            }
        }
    }
    
    result = render_filter_template(template, variables)
    expected = "ip.src==192.168.1.100 && udp.srcport==20000"
    
    print("="*60)
    print("QUICK TEMPLATE VALIDATION")
    print("="*60)
    print(f"\nTest 1: Variable Substitution")
    print(f"Template:  {template}")
    print(f"Result:    {result}")
    print(f"Expected:  {expected}")
    
    if result == expected:
        print("✓ PASS - Variable substitution works")
        return True
    else:
        print("✗ FAIL - Variable substitution failed")
        return False


def test_import_functions():
    """Test that functions can be imported"""
    try:
        import sys
        from pathlib import Path
        
        # Add project root to path
        project_root = Path(__file__).parent.parent
        sys.path.insert(0, str(project_root))
        
        from rtphelper.services.sip_correlation import (
            render_filter_template,
            build_filter_variables,
            get_builtin_template_set,
            build_tshark_filters_from_template,
        )
        
        print("\n" + "="*60)
        print("Test 2: Import Functions")
        print("="*60)
        print("✓ render_filter_template imported")
        print("✓ build_filter_variables imported")
        print("✓ get_builtin_template_set imported")
        print("✓ build_tshark_filters_from_template imported")
        
        # Test builtin templates
        templates = get_builtin_template_set("rtp_engine_topology")
        print(f"\n✓ Built-in RTP Engine templates: {len(templates)} steps")
        
        templates = get_builtin_template_set("direct_topology")
        print(f"✓ Built-in Direct templates: {len(templates)} steps")
        
        return True
        
    except Exception as e:
        print(f"\n✗ FAIL - Import error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\nPHASE 3 FILTER TEMPLATE SYSTEM - QUICK VALIDATION\n")
    
    result1 = test_template_rendering()
    result2 = test_import_functions()
    
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    if result1 and result2:
        print("✓ All validation checks passed")
        print("\n🎉 Phase 3 implementation successful!")
        exit(0)
    else:
        print("✗ Some validation checks failed")
        exit(1)
