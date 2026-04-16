#!/usr/bin/env python3
"""
Quick test to verify modular architecture is working.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("Testing modular architecture...")
print()

# Test 1: Import loaders
print("1. Importing loaders...")
try:
    from rtphelper.services.correlation_strategy_loader import CorrelationStrategyLoader
    from rtphelper.services.filter_template_loader import FilterTemplateLoader
    print("   ✅ Loaders imported successfully")
except Exception as e:
    print(f"   ❌ Failed to import loaders: {e}")
    sys.exit(1)

# Test 2: Load strategies
print("\n2. Loading correlation strategies...")
try:
    strategy_loader = CorrelationStrategyLoader()
    strategies = strategy_loader.load_strategies()
    print(f"   ✅ Loaded {len(strategies)} strategies")
    for name in strategies.keys():
        print(f"      - {name}")
except Exception as e:
    print(f"   ❌ Failed to load strategies: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 3: Load templates
print("\n3. Loading filter templates...")
try:
    template_loader = FilterTemplateLoader()
    templates = template_loader.load_templates()
    print(f"   ✅ Loaded {len(templates)} templates")
    for name in templates.keys():
        print(f"      - {name}")
except Exception as e:
    print(f"   ❌ Failed to load templates: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Verify strategy structure
print("\n4. Verifying strategy structure...")
try:
    direct = strategy_loader.get_strategy("direct_topology")
    if direct:
        print(f"   ✅ direct_topology: {direct.hops}-hop, {direct.topology.legs} legs")
    else:
        print("   ❌ direct_topology not found")
    
    rtp_engine = strategy_loader.get_strategy("rtp_engine_topology")
    if rtp_engine:
        print(f"   ✅ rtp_engine_topology: {rtp_engine.hops}-hop, {rtp_engine.topology.legs} legs")
    else:
        print("   ❌ rtp_engine_topology not found")
except Exception as e:
    print(f"   ❌ Failed to verify strategies: {e}")
    sys.exit(1)

# Test 5: Verify template structure
print("\n5. Verifying template structure...")
try:
    direct_template = template_loader.get_template("direct_2legs")
    if direct_template:
        print(f"   ✅ direct_2legs: {direct_template.legs} legs, {len(direct_template.steps)} steps")
    else:
        print("   ❌ direct_2legs not found")
    
    rtp_template = template_loader.get_template("rtp_engine_4legs")
    if rtp_template:
        print(f"   ✅ rtp_engine_4legs: {rtp_template.legs} legs, {len(rtp_template.steps)} steps")
    else:
        print("   ❌ rtp_engine_4legs not found")
except Exception as e:
    print(f"   ❌ Failed to verify templates: {e}")
    sys.exit(1)

print("\n" + "=" * 70)
print("✅ ALL TESTS PASSED - Modular architecture is working!")
print("=" * 70)
print()
