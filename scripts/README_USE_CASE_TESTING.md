# Use Case Selection Testing Scripts

This directory contains two scripts for testing and validating SIP correlation use case selection.

## Scripts

### 1. check_use_case.py - Analyze Real PCAP Files

Analyzes a real SIP pcap file and shows which correlation use case would be selected.

**Usage:**
```bash
# Auto-detect direction
python scripts/check_use_case.py path/to/sip_capture.pcap

# Force inbound direction
python scripts/check_use_case.py path/to/sip_capture.pcap --direction inbound

# Force outbound direction
python scripts/check_use_case.py path/to/sip_capture.pcap --direction outbound
```

**Features:**
- Parses SIP pcap file
- Shows all Call-IDs found
- Groups related Call-IDs
- Identifies which use case would be selected
- Shows evaluation of all use cases in priority order
- Validates multi_call_id compatibility

**Example Output:**
```
================================================================================
SIP PCAP USE CASE ANALYZER
================================================================================
File: sip_capture.pcap
Path: /path/to/sip_capture.pcap

📋 Step 1: Parsing SIP pcap...
✅ Parsed successfully
   Total packets: 50
   Call-IDs found: 2

📞 Step 2: Analyzing Call-IDs...
   Found 2 Call-ID(s):
   1. 1332522000432026205918@32.30.252.52
      Messages: 25
   2. 35660116_88059327@10.35.9.210
      Messages: 25

   Call-ID groups: 1
   Group 1: 2 Call-ID(s)
      - 1332522000432026205918@32.30.252.52
      - 35660116_88059327@10.35.9.210

   Primary group: 2 Call-ID(s)
   Auto-detected direction: inbound

🔍 Step 3: Identifying use case...
   Evaluating 32 use case(s) in priority order...

   → [1] inbound_b2bua_v2
      Priority: 90
      Direction: inbound
      multi_call_id: True
      Status: ✅ MATCHED
      ⭐ THIS CASE SELECTED

   [2] inbound_rtp_engine_v2
      Priority: 80
      Direction: inbound
      multi_call_id: False
      Status: ❌ skipped

   [3] inbound_direct_v2
      Priority: 10
      Direction: inbound
      multi_call_id: False
      Status: ❌ skipped

================================================================================
RESULT
================================================================================
✅ Selected Use Case: inbound_b2bua_v2
   Priority: 90
   Description: Inbound calls with B2BUA (multiple Call-IDs)
   Strategy: rtp_engine_topology
   multi_call_id: True
   Direction: inbound

🔍 Compatibility Analysis:
   ✅ Call-ID count: 2 (compatible with multi_call_id=True)
   ✅ Strategy: rtp_engine_topology (modular architecture)
================================================================================
```

### 2. test_use_case_selection.py - Test Scenarios Without PCAP

Tests use case selection with mock scenarios (no real pcap needed).

**Usage:**
```bash
python scripts/test_use_case_selection.py
```

**Features:**
- Creates mock SIP calls for testing
- Tests different scenarios (1 Call-ID, 2 Call-IDs, inbound, outbound)
- Validates priority ordering
- Validates multi_call_id protection
- Shows evaluation details for each scenario

**Example Output:**
```
================================================================================
USE CASE SELECTION TEST SUITE
================================================================================

Testing different scenarios to validate use case selection logic
with priorities and multi_call_id validation.

================================================================================
SCENARIO: Inbound with 1 Call-ID
================================================================================
Direction: inbound
Call-IDs: 1

Selected Use Case: test_templates_rtp_engine
  Priority: 100
  Strategy: configurable
  multi_call_id: None
  Description: Test case for RTP Engine filter templates

Top 5 evaluated cases:
  1. ✅ test_templates_rtp_engine (priority=100, multi_call_id=None)
  2. ❌ test_templates_direct (priority=100, multi_call_id=None)
  3. ❌ test_templates_custom (priority=100, multi_call_id=None)
  4. ❌ test_configurable_inbound (priority=100, multi_call_id=None)
  5. ❌ test_config (priority=100, multi_call_id=None)

================================================================================
SCENARIO: Inbound with 2 Call-IDs (multiple)
================================================================================
Direction: inbound
Call-IDs: 2

Selected Use Case: test_templates_rtp_engine
  Priority: 100
  Strategy: configurable
  multi_call_id: None
  Description: Test case for RTP Engine filter templates

Top 5 evaluated cases:
  1. ✅ test_templates_rtp_engine (priority=100, multi_call_id=None)
  2. ❌ test_templates_direct (priority=100, multi_call_id=None)
  3. ❌ test_templates_custom (priority=100, multi_call_id=None)
  4. ❌ test_configurable_inbound (priority=100, multi_call_id=None)
  5. ❌ inbound_b2bua_v2 (priority=90, multi_call_id=True)

================================================================================
SUMMARY
================================================================================

V2 Use Cases Priorities:
   90 - inbound_b2bua_v2               (multi_call_id=True)
   90 - outbound_b2bua_v2              (multi_call_id=True)
   80 - inbound_rtp_engine_v2          (multi_call_id=False)
   80 - outbound_rtp_engine_v2         (multi_call_id=False)
   10 - inbound_direct_v2              (multi_call_id=False)
   10 - outbound_direct_v2             (multi_call_id=False)

Expected behavior:
  - Specific cases (b2bua, rtp_engine) have higher priority than generic (direct)
  - multi_call_id=false cases should be skipped when num_call_ids > 1
  - multi_call_id=true cases should be skipped when num_call_ids == 1

Tests: 4/4 passed
================================================================================
```

## Understanding Use Case Selection

### Priority Order (Higher = Evaluated First)
- **90**: B2BUA cases (most specific - requires header check + multi Call-ID)
- **80**: RTP Engine cases (specific - single Call-ID)
- **10**: Direct media cases (generic fallback - single Call-ID)

### multi_call_id Protection
- `multi_call_id: false` → Only matches calls with 1 Call-ID
- `multi_call_id: true` → Only matches calls with 2+ Call-IDs
- `multi_call_id: null` → No constraint (legacy cases)

### Selection Algorithm
1. Load all use cases sorted by priority (highest first)
2. For each use case:
   - Check direction match
   - Check multi_call_id compatibility (NEW protection)
   - Check header requirements
   - If all checks pass → SELECT this case
3. Return first matching case

## Common Issues

### Issue: Wrong use case selected with multiple Call-IDs
**Symptom:** `inbound_direct_v2` selected when 2 Call-IDs exist

**Cause:** Priority too high or missing multi_call_id validation

**Fix:** 
- Lower priority for generic cases (direct should be 10)
- Ensure multi_call_id is set correctly in YAML

### Issue: No use case matches
**Symptom:** "unknown" use case selected

**Cause:** All use cases rejected (possibly incorrect multi_call_id config)

**Fix:** Check multi_call_id values match actual Call-ID count

## Testing Your Changes

After modifying priorities or multi_call_id settings:

1. **Test with mock scenarios:**
   ```bash
   python scripts/test_use_case_selection.py
   ```

2. **Test with real pcap:**
   ```bash
   python scripts/check_use_case.py path/to/your/sip.pcap
   ```

3. **Quick validation:**
   ```bash
   python -c "
   from rtphelper.services.correlation_case_loader import CorrelationCaseLoader
   loader = CorrelationCaseLoader()
   v2 = [(c.name, c.priority, c.correlation.multi_call_id) 
         for c in loader.get_cases() if c.name.endswith('_v2')]
   for name, prio, multi in sorted(v2, key=lambda x: x[1], reverse=True):
       print(f'{prio:3d} {name:30s} multi_call_id={multi}')
   "
   ```

## Validation Checklist

- [ ] B2BUA cases have priority 90
- [ ] RTP Engine cases have priority 80
- [ ] Direct media cases have priority 10
- [ ] B2BUA cases have `multi_call_id: true`
- [ ] RTP Engine cases have `multi_call_id: false`
- [ ] Direct media cases have `multi_call_id: false`
- [ ] Cases with `multi_call_id: false` are rejected when 2+ Call-IDs exist
- [ ] Cases with `multi_call_id: true` are rejected when 1 Call-ID exists
