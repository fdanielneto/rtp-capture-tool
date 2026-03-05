#!/usr/bin/env python3
"""
Test script for Phase 3: Filter Template System

Tests:
1. Template rendering engine (variable substitution)
2. Conditional logic (if/else)
3. Built-in template sets (rtp_engine_topology, direct_topology)
4. Custom templates from YAML
5. Integration with CorrelationCase and build_tshark_filters_from_template()
"""
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
    CorrelationContext,
    CorrelationLeg,
    MediaEndpoint,
    RtpEngineDetection,
)
from rtphelper.services.correlation_case_loader import get_loader


def test_variable_substitution():
    """Test 1: Variable substitution in templates"""
    print("\n" + "="*60)
    print("TEST 1: Variable Substitution")
    print("="*60)
    
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
    
    print(f"Template:  {template}")
    print(f"Variables: {variables}")
    print(f"Result:    {result}")
    print(f"Expected:  {expected}")
    print(f"✓ PASS" if result == expected else f"✗ FAIL")
    
    return result == expected


def test_conditionals_inbound():
    """Test 2: Conditional logic - inbound direction"""
    print("\n" + "="*60)
    print("TEST 2: Conditional Logic (Inbound)")
    print("="*60)
    
    template = """{% if direction == "inbound" %}ip.src==${carrier.source.ip}{% else %}ip.dst==${carrier.destination.ip}{% endif %}"""
    variables = {
        "direction": "inbound",
        "carrier": {
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "10.0.0.2"}
        }
    }
    
    result = render_filter_template(template, variables)
    expected = "ip.src==10.0.0.1"
    
    print(f"Template:  {template}")
    print(f"Direction: {variables['direction']}")
    print(f"Result:    {result}")
    print(f"Expected:  {expected}")
    print(f"✓ PASS" if result == expected else f"✗ FAIL")
    
    return result == expected


def test_conditionals_outbound():
    """Test 3: Conditional logic - outbound direction"""
    print("\n" + "="*60)
    print("TEST 3: Conditional Logic (Outbound)")
    print("="*60)
    
    template = """{% if direction == "inbound" %}ip.src==${carrier.source.ip}{% else %}ip.dst==${carrier.destination.ip}{% endif %}"""
    variables = {
        "direction": "outbound",
        "carrier": {
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "10.0.0.2"}
        }
    }
    
    result = render_filter_template(template, variables)
    expected = "ip.dst==10.0.0.2"
    
    print(f"Template:  {template}")
    print(f"Direction: {variables['direction']}")
    print(f"Result:    {result}")
    print(f"Expected:  {expected}")
    print(f"✓ PASS" if result == expected else f"✗ FAIL")
    
    return result == expected


def test_nested_conditionals():
    """Test 4: Nested conditionals with RTP Engine detection"""
    print("\n" + "="*60)
    print("TEST 4: Nested Conditionals (RTP Engine)")
    print("="*60)
    
    template = """{% if rtpengine.detected %}{% if direction == "inbound" %}ip.src==${rtpengine.detected_ip}{% else %}ip.dst==${rtpengine.detected_ip}{% endif %}{% else %}ip.src==${carrier.source.ip}{% endif %}"""
    
    # Test with RTP Engine detected
    variables = {
        "direction": "inbound",
        "rtpengine": {
            "detected": True,
            "detected_ip": "172.16.0.1"
        },
        "carrier": {
            "source": {"ip": "10.0.0.1"}
        }
    }
    
    result = render_filter_template(template, variables)
    expected = "ip.src==172.16.0.1"
    
    print(f"Template:      {template}")
    print(f"RTP Detected:  {variables['rtpengine']['detected']}")
    print(f"Direction:     {variables['direction']}")
    print(f"Result:        {result}")
    print(f"Expected:      {expected}")
    print(f"✓ PASS" if result == expected else f"✗ FAIL")
    
    return result == expected


def test_builtin_rtp_engine_templates():
    """Test 5: Built-in RTP Engine template set"""
    print("\n" + "="*60)
    print("TEST 5: Built-in RTP Engine Templates")
    print("="*60)
    
    templates = get_builtin_template_set("rtp_engine_topology")
    
    print(f"Template set: rtp_engine_topology")
    print(f"Number of steps: {len(templates)}")
    
    for template in templates:
        print(f"\n  Step {template['step']}: {template['leg_name']}")
        print(f"    Key: {template['leg_key']}")
        print(f"    Description: {template['description']}")
        print(f"    Required: {', '.join(template['required_fields'])}")
    
    success = len(templates) == 4
    print(f"\n{'✓ PASS' if success else '✗ FAIL'} - Expected 4 steps")
    
    return success


def test_builtin_direct_templates():
    """Test 6: Built-in direct topology template set"""
    print("\n" + "="*60)
    print("TEST 6: Built-in Direct Topology Templates")
    print("="*60)
    
    templates = get_builtin_template_set("direct_topology")
    
    print(f"Template set: direct_topology")
    print(f"Number of steps: {len(templates)}")
    
    for template in templates:
        print(f"\n  Step {template['step']}: {template['leg_name']}")
        print(f"    Key: {template['leg_key']}")
        print(f"    Description: {template['description']}")
        print(f"    Required: {', '.join(template['required_fields'])}")
    
    success = len(templates) == 2
    print(f"\n{'✓ PASS' if success else '✗ FAIL'} - Expected 2 steps")
    
    return success


def test_build_filter_variables():
    """Test 7: Build filter variables from CorrelationContext"""
    print("\n" + "="*60)
    print("TEST 7: Build Filter Variables")
    print("="*60)
    
    # Create mock correlation context
    ctx = CorrelationContext(
        direction="inbound",
        call_ids=["test-call-id"]
    )
    
    ctx.carrier_leg = CorrelationLeg(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        source_media=MediaEndpoint(rtp_ip="192.168.1.100", rtp_port=20000),
        destination_media=MediaEndpoint(rtp_ip="10.0.0.1", rtp_port=30000)
    )
    
    ctx.core_leg = CorrelationLeg(
        source_ip="10.0.0.2",
        destination_ip="10.0.0.3",
        source_media=MediaEndpoint(rtp_ip="10.0.0.2", rtp_port=40000),
        destination_media=MediaEndpoint(rtp_ip="10.0.0.3", rtp_port=50000)
    )
    
    ctx.rtp_engine = RtpEngineDetection(
        detected=True,
        changed_sdp_ip="172.16.0.1"
    )
    
    variables = build_filter_variables(ctx, rtpengine_actual_ip="172.16.10.1", for_count=False)
    
    print(f"Direction: {variables['direction']}")
    print(f"For count: {variables['for_count']}")
    print(f"RTP Engine detected: {variables['rtpengine']['detected']}")
    print(f"RTP Engine detected IP: {variables['rtpengine']['detected_ip']}")
    print(f"\nCarrier leg:")
    print(f"  Source IP: {variables['carrier']['source']['ip']}")
    print(f"  Source Port: {variables['carrier']['source']['port']}")
    print(f"  Dest IP: {variables['carrier']['destination']['ip']}")
    print(f"  Dest Port: {variables['carrier']['destination']['port']}")
    print(f"\nCore leg:")
    print(f"  Source IP: {variables['core']['source']['ip']}")
    print(f"  Source Port: {variables['core']['source']['port']}")
    print(f"  Dest IP: {variables['core']['destination']['ip']}")
    print(f"  Dest Port: {variables['core']['destination']['port']}")
    
    success = (
        variables['direction'] == 'inbound' and
        variables['carrier']['source']['ip'] == '192.168.1.100' and
        variables['core']['destination']['port'] == 50000
    )
    
    print(f"\n{'✓ PASS' if success else '✗ FAIL'}")
    
    return success


def test_build_filters_from_template():
    """Test 8: Build tshark filters from template"""
    print("\n" + "="*60)
    print("TEST 8: Build Filters from Template")
    print("="*60)
    
    # Create mock correlation context
    ctx = CorrelationContext(
        direction="inbound",
        call_ids=["test-call-id"]
    )
    
    ctx.carrier_leg = CorrelationLeg(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        source_media=MediaEndpoint(rtp_ip="192.168.1.100", rtp_port=20000),
        destination_media=MediaEndpoint(rtp_ip="10.0.0.1", rtp_port=30000)
    )
    
    ctx.core_leg = CorrelationLeg(
        source_ip="10.0.0.2",
        destination_ip="10.0.0.3",
        source_media=MediaEndpoint(rtp_ip="10.0.0.2", rtp_port=40000),
        destination_media=MediaEndpoint(rtp_ip="10.0.0.3", rtp_port=50000)
    )
    
    ctx.rtp_engine = RtpEngineDetection(
        detected=True,
        changed_sdp_ip="10.0.0.1"
    )
    
    # Build filters using RTP Engine template set
    filters = build_tshark_filters_from_template(
        ctx,
        template_set_name="rtp_engine_topology",
        rtpengine_actual_ip="172.16.10.1",
        for_count=False
    )
    
    print(f"\nGenerated {len(filters)} filter steps:\n")
    for f in filters:
        status = "✓" if f['available'] else "✗"
        print(f"{status} Step {f['step']}: {f['leg']}")
        if f['available']:
            print(f"    Filter: {f['tshark_filter']}")
        else:
            print(f"    Unavailable: {f['reason']}")
    
    success = len(filters) == 4 and all(f['available'] for f in filters)
    print(f"\n{'✓ PASS' if success else '✗ FAIL'} - All 4 steps available")
    
    return success


def test_yaml_template_loading():
    """Test 9: Load templates from YAML configuration"""
    print("\n" + "="*60)
    print("TEST 9: Load Templates from YAML")
    print("="*60)
    
    loader = get_loader()
    cases = loader.load_cases()
    
    # Find test cases with templates
    template_cases = [case for case in cases if case.filters and case.filters.template_set]
    
    print(f"Loaded {len(cases)} total cases")
    print(f"Found {len(template_cases)} cases with filter templates:\n")
    
    for case in template_cases:
        print(f"  • {case.name}")
        print(f"    Template set: {case.filters.template_set}")
        print(f"    Custom templates: {case.filters.custom_templates_enabled}")
        if case.filters.custom_templates_enabled:
            print(f"    Custom steps: {len(case.filters.steps)}")
    
    success = len(template_cases) >= 2
    print(f"\n{'✓ PASS' if success else '✗ FAIL'} - Found test cases with templates")
    
    return success


def test_custom_templates_from_yaml():
    """Test 10: Custom templates from YAML with conditionals"""
    print("\n" + "="*60)
    print("TEST 10: Custom Templates from YAML")
    print("="*60)
    
    loader = get_loader()
    cases = loader.load_cases()
    
    # Find custom template case
    custom_case = None
    for case in cases:
        if case.name == "test_templates_custom":
            custom_case = case
            break
    
    if not custom_case:
        print("✗ FAIL - test_templates_custom case not found")
        return False
    
    print(f"Case: {custom_case.name}")
    print(f"Custom templates enabled: {custom_case.filters.custom_templates_enabled}")
    print(f"Number of custom steps: {len(custom_case.filters.steps)}\n")
    
    # Create mock context
    ctx = CorrelationContext(
        direction="inbound",
        call_ids=["test-call-id"]
    )
    
    ctx.carrier_leg = CorrelationLeg(
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        source_media=MediaEndpoint(rtp_ip="192.168.1.100", rtp_port=20000),
        destination_media=MediaEndpoint(rtp_ip="10.0.0.1", rtp_port=30000)
    )
    
    ctx.core_leg = CorrelationLeg(
        source_ip="10.0.0.2",
        destination_ip="10.0.0.3",
        source_media=MediaEndpoint(rtp_ip="10.0.0.2", rtp_port=40000),
        destination_media=MediaEndpoint(rtp_ip="10.0.0.3", rtp_port=50000)
    )
    
    ctx.rtp_engine = RtpEngineDetection(detected=True, changed_sdp_ip="10.0.0.1")
    
    # Convert FilterStepTemplate dataclass to dict for build_tshark_filters_from_template
    custom_templates = []
    for step_template in custom_case.filters.steps:
        custom_templates.append({
            "step": step_template.step,
            "leg_name": step_template.leg_name,
            "leg_key": step_template.leg_key,
            "description": step_template.description,
            "phase1_template": step_template.phase1_template,
            "phase2_template": step_template.phase2_template,
            "required_fields": step_template.required_fields
        })
    
    # Build filters using custom templates
    filters = build_tshark_filters_from_template(
        ctx,
        template_set_name="custom",
        rtpengine_actual_ip="172.16.10.1",
        for_count=False,
        custom_templates=custom_templates
    )
    
    print(f"Generated {len(filters)} filter steps from custom templates:\n")
    for f in filters:
        status = "✓" if f['available'] else "✗"
        print(f"{status} Step {f['step']}: {f['leg']}")
        if f['available']:
            print(f"    Filter: {f['tshark_filter']}")
        else:
            print(f"    Unavailable: {f['reason']}")
    
    success = len(filters) == 4 and all(f['available'] for f in filters)
    print(f"\n{'✓ PASS' if success else '✗ FAIL'} - All custom template steps rendered")
    
    return success


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("FILTER TEMPLATE SYSTEM VALIDATION")
    print("Phase 3: Template Rendering Engine")
    print("="*60)
    
    results = []
    
    # Run all tests
    results.append(("Variable Substitution", test_variable_substitution()))
    results.append(("Conditionals (Inbound)", test_conditionals_inbound()))
    results.append(("Conditionals (Outbound)", test_conditionals_outbound()))
    results.append(("Nested Conditionals", test_nested_conditionals()))
    results.append(("Built-in RTP Engine Templates", test_builtin_rtp_engine_templates()))
    results.append(("Built-in Direct Templates", test_builtin_direct_templates()))
    results.append(("Build Filter Variables", test_build_filter_variables()))
    results.append(("Build Filters from Template", test_build_filters_from_template()))
    results.append(("YAML Template Loading", test_yaml_template_loading()))
    results.append(("Custom Templates from YAML", test_custom_templates_from_yaml()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} {name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Phase 3 implementation successful.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Review implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
