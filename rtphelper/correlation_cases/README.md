# Correlation Cases Configuration

This directory contains correlation case definitions. Each YAML file represents a use case for SIP call correlation.

## File Structure

Each file should be named descriptively (e.g., `inbound_pstn_carrier.yaml`) and contain:

```yaml
name: unique_case_identifier
description: Human-readable description
priority: 10  # Higher priority cases are checked first (default: 10)
enabled: true  # Set to false to disable without deleting

detection:
  direction: inbound  # "inbound", "outbound", or "both"
  headers:
    - pattern: "diversion:"
      case_insensitive: true
      required: false  # If true, case only matches if header is present
  method: INVITE  # Optional: only check specific SIP methods

correlation:
  strategy: generic  # Strategy to use: "generic", "configurable", or class path
  force_direction: inbound  # Force this direction regardless of input
  annotations:
    - "Correlator: InboundPSTNCarrierCorrelator"  # Add to log lines
  
  # Runtime behavior configuration (optional)
  config:
    # IP extraction rules
    carrier_ip_source: first_invite.src_ip  # How to determine carrier IP
    core_ip_source: last_invite.dst_ip      # How to determine core IP
    
    # Response finding strategy
    response_priority: [183, 200]  # Try 183 first, fallback to 200
    enable_hop_fallback: true
    enable_adjacent_packet_search: true
    block_xcc_responses: true
    
    # RTP Engine detection
    rtp_engine_detection: enabled  # "enabled", "disabled", "optional"
    xcc_ip_source: invite_with_changed_sdp.src_ip
    
    # Special handling
    filter_reinvites: true
    group_multi_call_ids: true
  
  notes: |
    Optional multi-line notes about this use case

# Filter configuration (optional)
filters:
  template_set: rtp_engine_topology  # "rtp_engine_topology", "direct_topology"
  use_default_templates: true
  
  # Custom filter templates (optional)
  custom_templates:
    enabled: false
    steps:
      - step: 1
        leg_name: carrier->host
        leg_key: leg_carrier_rtpengine
        # Phase 1 = packet counting / pre-filter stage
        phase1_template: "ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}"
        # Phase 2 = per-leg extraction stage
        phase2_template: "ip.src==${carrier.source.ip} && udp.srcport==${carrier.source.port}"
        required_fields: [carrier.source.ip, carrier.source.port]
```

## Adding New Use Cases

1. Create a new `.yaml` file in this directory
2. Define detection rules and correlation strategy
3. (Optional) Add correlation behavior config for custom IP extraction and response handling
4. (Optional) Add filters config for custom filter templates
5. Restart the application to load the new case
6. Test with appropriate SIP traffic

## Configuration Options

### Correlation Behavior Config

The `correlation.config` section allows customizing runtime correlation behavior:

**IP Extraction Sources:**
- `carrier_ip_source`: How to determine carrier IP
  - `first_invite.src_ip` - Source of first INVITE (typical for inbound)
  - `last_invite.dst_ip` - Destination of last INVITE (typical for inbound core)
  - `first_invite.dst_ip` - Destination of first INVITE
  - More options available (see configurable_example.yaml.example)

- `core_ip_source`: How to determine core IP

**Response Finding:**
- `response_priority`: Order to try response types, e.g., `[183, 200]` or `[200]`
- `enable_hop_fallback`: Use hop-based fallback when direct response not found
- `enable_adjacent_packet_search`: Check adjacent packets for incomplete SDP
- `block_xcc_responses`: Prevent using responses from B2BUA server

**RTP Engine Detection:**
- `rtp_engine_detection`: `"enabled"`, `"disabled"`, or `"optional"`
- `xcc_ip_source`: How to identify XCC/B2BUA server IP

**Special Handling:**
- `filter_reinvites`: Distinguish initial INVITE from re-INVITE
- `group_multi_call_ids`: Group calls by X-Talkdesk-Other-Leg-Call-Id

### Filters Config

The `filters` section allows customizing filter generation:

**Template Sets:**
- `rtp_engine_topology`: 4-leg topology (Carrier ↔ RTP Engine ↔ Core)
- `direct_topology`: 2-leg topology (Carrier ↔ Core)

**Custom Templates:**
- Define custom filter expressions with variable substitution
- Support for Phase 1 (packet counting / pre-filter) and Phase 2 (per-leg extraction) filtering
- Jinja2-style conditionals: `{% if direction == 'inbound' %}`

See `configurable_example.yaml.example` for complete examples.

## Priority System

Cases are evaluated in descending priority order:
- Priority 100: Critical/specific cases
- Priority 50: Common cases (e.g., inbound_pstn_carrier)
- Priority 30-80: Fallback cases (extracted from generic correlation logic)
- Priority 10: Generic fallbacks (default)
- Priority 0: Catch-all

If no case matches, the "unknown" generic correlator is used.

## Fallback Cases

**10 fallback cases** extracted from the generic correlation logic (`build_correlation_context()` function):

### Topology Cases (Priority 41-45)
- `inbound_with_rtp_engine-fallback.yaml` (P:45) - Carrier → RTP Engine → Core
- `inbound_no_rtp_engine-fallback.yaml` (P:42) - Carrier → Core (direct)
- `outbound_with_rtp_engine-fallback.yaml` (P:44) - Core → RTP Engine → Carrier
- `outbound_no_rtp_engine-fallback.yaml` (P:41) - Core → Carrier (direct)

### SIP Feature Cases (Priority 65-75)
- `early_media_183-fallback.yaml` (P:70) - 183 Session Progress prioritization
- `incomplete_sdp-fallback.yaml` (P:65) - Adjacent packet fallback for missing SDP
- `reinvite_detection-fallback.yaml` (P:68) - Distinguishes initial INVITE from re-INVITE
- `multi_call_id_b2bua-fallback.yaml` (P:75) - B2BUA with X-Talkdesk-Other-Leg-Call-Id

### Fallback Mechanisms (Priority 30, 80)
- `response_hop_fallback-fallback.yaml` (P:30) - Response discovery at adjacent hops
- `xcc_fallback_blocked-fallback.yaml` (P:80) - Prevents using B2BUA server responses

See [CORRELATION_FALLBACK_CASES.md](../../docs/CORRELATION_FALLBACK_CASES.md) for detailed documentation.
