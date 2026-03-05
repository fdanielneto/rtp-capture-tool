#!/usr/bin/env python3
"""Quick smoke test for correlation strategy pattern implementation."""

import sys

try:
    from rtphelper.services.sip_correlation import (
        correlate_sip_call,
        USE_CASE_HANDLERS,
        CorrelationStrategy,
        GenericCorrelator,
        InboundPSTNCarrierCorrelator,
        OutboundPSTNCarrierCorrelator,
        identify_use_case,
    )
    
    print("✓ Import successful")
    print(f"✓ {len(USE_CASE_HANDLERS)} use case handlers registered")
    print(f"✓ Handlers: {list(USE_CASE_HANDLERS.keys())}")
    
    # Verify all handlers are CorrelationStrategy instances
    for name, handler in USE_CASE_HANDLERS.items():
        assert isinstance(handler, CorrelationStrategy), f"Handler '{name}' is not a CorrelationStrategy"
    print(f"✓ All handlers are CorrelationStrategy instances")
    
    # Verify GenericCorrelator exists
    assert GenericCorrelator is not None
    print(f"✓ GenericCorrelator class available")
    
    # Verify InboundPSTNCarrierCorrelator exists
    assert InboundPSTNCarrierCorrelator is not None
    print(f"✓ InboundPSTNCarrierCorrelator class available")
    
    # Verify OutboundPSTNCarrierCorrelator exists
    assert OutboundPSTNCarrierCorrelator is not None
    print(f"✓ OutboundPSTNCarrierCorrelator class available")
    
    # Verify identify_use_case exists
    assert callable(identify_use_case)
    print(f"✓ identify_use_case function available")
    
    # Verify handler types in registry
    assert isinstance(USE_CASE_HANDLERS["unknown"], GenericCorrelator)
    print(f"✓ 'unknown' handler is GenericCorrelator")
    
    assert isinstance(USE_CASE_HANDLERS["inbound_pstn_carrier"], InboundPSTNCarrierCorrelator)
    print(f"✓ 'inbound_pstn_carrier' handler is InboundPSTNCarrierCorrelator")
    
    assert isinstance(USE_CASE_HANDLERS["outbound_pstn_carrier"], OutboundPSTNCarrierCorrelator)
    print(f"✓ 'outbound_pstn_carrier' handler is OutboundPSTNCarrierCorrelator")
    
    print("\n✅ All smoke tests passed! Phase 2 implementation validated.")
    sys.exit(0)
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
