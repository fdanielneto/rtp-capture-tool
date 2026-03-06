#!/usr/bin/env python3
"""
Script to analyze a SIP pcap and determine which correlation use case would be selected.

Usage:
    python scripts/check_use_case.py <pcap_file> [--direction inbound|outbound]

Example:
    python scripts/check_use_case.py sip_capture.pcap
    python scripts/check_use_case.py sip_capture.pcap --direction inbound
"""

import sys
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List

import yaml

# Add rtphelper to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.sip_parser import parse_sip_pcap
from rtphelper.services.sip_correlation import (
    identify_use_case,
    group_related_calls,
    merge_calls_by_group,
    _matches_case,
    correlate_sip_call,
    build_tshark_filters,
    build_tshark_filters_from_template,
    build_filter_variables,
    render_filter_template,
    get_builtin_template_set,
)
from rtphelper.services.correlation_case_loader import CorrelationCaseLoader
from rtphelper.services.filter_template_loader import get_template as get_filter_template


def _get_template_name_from_case(case) -> Optional[str]:
    """Resolve template name from case YAML (supports legacy and modular keys)."""
    if case.filters and case.filters.template_set:
        return case.filters.template_set

    if not case.file_path:
        return None

    try:
        with open(case.file_path, "r", encoding="utf-8") as f:
            case_yaml = yaml.safe_load(f) or {}
        filters_yaml = case_yaml.get("filters", {}) if isinstance(case_yaml, dict) else {}
        template_name = filters_yaml.get("template") or filters_yaml.get("template_set")
        return str(template_name).strip() if template_name else None
    except Exception:
        return None


def _get_custom_steps_from_case(case) -> Optional[List[Dict[str, Any]]]:
    """Resolve custom filter steps if present in case YAML."""
    if case.filters and case.filters.custom_templates_enabled and case.filters.steps:
        steps: List[Dict[str, Any]] = []
        for step in case.filters.steps:
            steps.append(
                {
                    "step": step.step,
                    "leg_name": step.leg_name,
                    "leg_key": step.leg_key,
                    "description": step.description,
                    "phase1_template": step.phase1_template,
                    "phase2_template": step.phase2_template,
                    "required_fields": step.required_fields,
                }
            )
        return steps

    if not case.file_path:
        return None

    try:
        with open(case.file_path, "r", encoding="utf-8") as f:
            case_yaml = yaml.safe_load(f) or {}
        filters_yaml = case_yaml.get("filters", {}) if isinstance(case_yaml, dict) else {}
        custom_enabled = bool(filters_yaml.get("custom_templates_enabled", False))
        if not custom_enabled:
            return None
        steps = filters_yaml.get("steps")
        if isinstance(steps, list):
            return steps
    except Exception:
        return None

    return None


def _compact_filter(text: str) -> str:
    """Convert multi-line template/filter into single-line expression for display."""
    return " ".join(line.strip() for line in str(text).splitlines() if line.strip())


def _get_template_step_map(
    template_name: Optional[str],
    custom_steps: Optional[List[Dict[str, Any]]],
    for_count: bool,
) -> Dict[str, str]:
    """Return leg_key -> template expression (phase1 for count, phase2 for per-leg)."""
    key = "phase1_template" if for_count else "phase2_template"
    step_map: Dict[str, str] = {}

    if custom_steps:
        for step in custom_steps:
            leg_key = str(step.get("leg_key") or step.get("leg_name") or "")
            expr = _compact_filter(step.get(key, ""))
            if leg_key and expr:
                step_map[leg_key] = expr
        return step_map

    if not template_name:
        return step_map

    try:
        tpl = get_filter_template(template_name)
        if not tpl:
            return step_map
        for step in tpl.steps:
            leg_key = str(step.leg_key or step.leg_name or "")
            expr = _compact_filter(step.phase1_template if for_count else step.phase2_template)
            if leg_key and expr:
                step_map[leg_key] = expr
    except Exception:
        return step_map

    return step_map


def _get_template_steps(
    template_name: Optional[str],
    custom_steps: Optional[List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Return full template steps from custom, YAML, or built-in source."""
    if custom_steps:
        return custom_steps

    if template_name:
        try:
            tpl = get_filter_template(template_name)
            if tpl:
                return [
                    {
                        "step": step.step,
                        "leg_name": step.leg_name,
                        "leg_key": step.leg_key,
                        "description": step.description,
                        "phase1_template": step.phase1_template,
                        "phase2_template": step.phase2_template,
                        "required_fields": step.required_fields,
                    }
                    for step in tpl.steps
                ]
        except Exception:
            pass

        try:
            return get_builtin_template_set(template_name)
        except Exception:
            return []

    return []


def _get_nested_value(data: Dict[str, Any], field_path: str) -> Any:
    """Get nested value from dict using dot notation."""
    value: Any = data
    for part in field_path.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = getattr(value, part, None)
        if value is None:
            return None
    return value


def _set_nested_value(data: Dict[str, Any], field_path: str, value: Any) -> None:
    """Set nested value in dict using dot notation."""
    parts = field_path.split(".")
    target = data
    for part in parts[:-1]:
        current = target.get(part)
        if not isinstance(current, dict):
            current = {}
            target[part] = current
        target = current
    target[parts[-1]] = value


def _enrich_template_variables(variables: Dict[str, Any]) -> Dict[str, Any]:
    """Add compatibility aliases expected by some templates."""
    # Ensure RTP Engine public SDP IP is available from SIP context when not explicit.
    public_ip = _get_nested_value(variables, "rtpengine.public_ip")
    if not public_ip:
        public_ip = (
            _get_nested_value(variables, "core.source.ip")
            or _get_nested_value(variables, "core.destination.ip")
            or _get_nested_value(variables, "carrier.destination.ip")
        )
        if public_ip:
            _set_nested_value(variables, "rtpengine.public_ip", public_ip)
            _set_nested_value(variables, "rtpengine.sdp_ip", public_ip)

    # Some templates use rtpengine.source.port (non-canonical alias).
    source_port = (
        _get_nested_value(variables, "core.source.port")
        or _get_nested_value(variables, "carrier.destination.port")
        or _get_nested_value(variables, "carrier.source.port")
    )
    if source_port:
        _set_nested_value(variables, "rtpengine.source.port", source_port)
    return variables


def _render_steps_with_values(
    template_steps: List[Dict[str, Any]],
    variables: Dict[str, Any],
    for_count: bool,
) -> List[Dict[str, Any]]:
    """Render each template step using provided variables, preserving placeholders for missing vars."""
    key = "phase1_template" if for_count else "phase2_template"
    rendered: List[Dict[str, Any]] = []
    for step in template_steps:
        template_expr = str(step.get(key) or "").strip()
        if not template_expr:
            continue
        rendered_expr = _compact_filter(render_filter_template(template_expr, variables))
        rendered.append(
            {
                "step": int(step.get("step") or 0),
                "leg_key": str(step.get("leg_key") or step.get("leg_name") or ""),
                "tshark_filter": rendered_expr,
            }
        )
    return rendered


def analyze_pcap(pcap_path: str, direction: Optional[str] = None) -> None:
    """
    Analyze a pcap and show which use case would be selected.
    
    Args:
        pcap_path: Path to the SIP pcap file
        direction: Optional forced direction (inbound/outbound)
    """
    pcap_file = Path(pcap_path)
    
    if not pcap_file.exists():
        print(f"❌ ERROR: File not found: {pcap_path}")
        sys.exit(1)
    
    print("=" * 80)
    print("SIP PCAP USE CASE ANALYZER")
    print("=" * 80)
    print(f"File: {pcap_file.name}")
    print(f"Path: {pcap_file.absolute()}")
    print()
    
    # Parse SIP pcap
    print("📋 Step 1: Parsing SIP pcap...")
    try:
        parse_result = parse_sip_pcap(pcap_file)
        print(f"✅ Parsed successfully")
        total_messages = sum(len(call.messages) for call in parse_result.calls.values())
        print(f"   Total SIP messages: {total_messages}")
        print(f"   Call-IDs found: {len(parse_result.calls)}")
    except Exception as e:
        print(f"❌ ERROR parsing pcap: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    if not parse_result.calls:
        print("❌ No SIP calls found in pcap")
        sys.exit(1)
    
    print()
    print("📞 Step 2: Analyzing Call-IDs...")
    print(f"   Found {len(parse_result.calls)} Call-ID(s):")
    for i, call_id in enumerate(parse_result.calls.keys(), 1):
        call = parse_result.calls[call_id]
        print(f"   {i}. {call_id}")
        print(f"      Messages: {len(call.messages)}")
    
    # Group related calls
    groups = group_related_calls(parse_result)
    print()
    print(f"   Call-ID groups: {len(groups)}")
    for i, group in enumerate(groups, 1):
        print(f"   Group {i}: {len(group)} Call-ID(s)")
        for call_id in sorted(group):
            print(f"      - {call_id}")
    
    # Get largest group
    target_group = max(groups, key=lambda g: sum(
        len(parse_result.calls[cid].messages) 
        for cid in g if cid in parse_result.calls
    )) if groups else set(parse_result.calls.keys())
    
    num_call_ids = len(target_group)
    print()
    print(f"   Primary group: {num_call_ids} Call-ID(s)")
    
    # Merge calls
    merged_call = merge_calls_by_group(parse_result, target_group)
    
    # Auto-detect direction if not specified
    if direction is None:
        # Simple heuristic: check first INVITE direction
        # (more sophisticated logic could be added)
        for msg in merged_call.messages:
            if msg.is_request and msg.method == "INVITE":
                # Check if dst_ip is internal (simplistic check)
                # You might want to add more sophisticated detection
                direction = "inbound"  # Default assumption
                break
        
        if direction is None:
            direction = "inbound"  # Fallback
        
        print(f"   Auto-detected direction: {direction}")
    else:
        print(f"   Forced direction: {direction}")
    
    print()
    print("🔍 Step 3: Identifying use case...")
    
    # Load all cases
    loader = CorrelationCaseLoader()
    cases = loader.get_cases()
    
    # Show which cases are being evaluated (sorted by priority)
    print(f"   Evaluating {len(cases)} use case(s) in priority order...")
    print()
    
    # Detailed analysis
    matched_case = None
    for i, case in enumerate(cases, 1):
        matches = _matches_case(merged_call, direction, case, num_call_ids=num_call_ids)
        
        # Show case info
        status = "✅ MATCHED" if matches else "❌ skipped"
        symbol = "→" if matches else " "
        
        print(f"   {symbol} [{i:2d}] {case.name}")
        print(f"      Priority: {case.priority}")
        print(f"      Direction: {case.detection.direction}")
        print(f"      multi_call_id: {case.correlation.multi_call_id}")
        print(f"      Status: {status}")
        
        if matches and matched_case is None:
            matched_case = case
            print(f"      ⭐ THIS CASE SELECTED")
        
        print()
    
    # Final result
    print("=" * 80)
    print("RESULT")
    print("=" * 80)
    
    if matched_case:
        print(f"✅ Selected Use Case: {matched_case.name}")
        print(f"   Priority: {matched_case.priority}")
        print(f"   Description: {matched_case.description}")
        print(f"   Strategy: {matched_case.correlation.strategy}")
        print(f"   multi_call_id: {matched_case.correlation.multi_call_id}")
        print(f"   Direction: {matched_case.detection.direction}")
        
        # Compatibility check
        print()
        print("🔍 Compatibility Analysis:")
        
        # Check Call-ID compatibility
        if matched_case.correlation.multi_call_id is not None:
            expected_multi = matched_case.correlation.multi_call_id
            actual_multi = num_call_ids > 1
            
            if expected_multi == actual_multi:
                print(f"   ✅ Call-ID count: {num_call_ids} (compatible with multi_call_id={expected_multi})")
            else:
                print(f"   ⚠️  Call-ID count: {num_call_ids} (MISMATCH: expects multi_call_id={expected_multi})")
        else:
            print(f"   ℹ️  Call-ID count: {num_call_ids} (no multi_call_id constraint)")
        
        # Check strategy
        strategy = matched_case.correlation.strategy
        if strategy in ["direct_topology", "rtp_engine_topology"]:
            print(f"   ✅ Strategy: {strategy} (modular architecture)")
        elif strategy == "configurable":
            print(f"   ℹ️  Strategy: {strategy} (legacy inline config)")
        else:
            print(f"   ℹ️  Strategy: {strategy}")

        # Build and show filters for selected use case
        print()
        print("🧪 Filters for selected use case:")
        try:
            ctx, _ = correlate_sip_call(
                parse_result=parse_result,
                direction=direction,
                use_case=matched_case.name,
            )

            template_name = _get_template_name_from_case(matched_case)
            custom_steps = _get_custom_steps_from_case(matched_case)
            template_steps = _get_template_steps(template_name, custom_steps)

            # Keep current availability diagnostics from production filter builder.
            if template_name or custom_steps:
                count_steps = build_tshark_filters_from_template(
                    ctx=ctx,
                    template_set_name=template_name or "",
                    rtpengine_actual_ip=None,
                    for_count=True,
                    custom_templates=custom_steps,
                )
                leg_steps = build_tshark_filters_from_template(
                    ctx=ctx,
                    template_set_name=template_name or "",
                    rtpengine_actual_ip=None,
                    for_count=False,
                    custom_templates=custom_steps,
                )
            else:
                count_steps = build_tshark_filters(ctx=ctx, rtpengine_actual_ip=None, for_count=True)
                leg_steps = build_tshark_filters(ctx=ctx, rtpengine_actual_ip=None, for_count=False)

            # Build display filters with SIP-derived values, matching app rendering logic.
            count_vars = _enrich_template_variables(build_filter_variables(ctx=ctx, rtpengine_actual_ip=None, for_count=True))
            leg_vars = _enrich_template_variables(build_filter_variables(ctx=ctx, rtpengine_actual_ip=None, for_count=False))

            # SIP-only analysis: resolved private RTP Engine IP is not derivable from SIP payload alone.
            # Keep explicit placeholder token in rendered output.
            _set_nested_value(leg_vars, "rtpengine.resolved_ip", "${rtpengine.resolved_ip}")

            rendered_count_steps = _render_steps_with_values(template_steps, count_vars, for_count=True)
            rendered_leg_steps = _render_steps_with_values(template_steps, leg_vars, for_count=False)

            rendered_count_map = {s["leg_key"]: s["tshark_filter"] for s in rendered_count_steps if s.get("leg_key")}
            rendered_leg_map = {s["leg_key"]: s["tshark_filter"] for s in rendered_leg_steps if s.get("leg_key")}

            count_template_map = _get_template_step_map(template_name, custom_steps, for_count=True)
            leg_template_map = _get_template_step_map(template_name, custom_steps, for_count=False)

            available_count = []
            for s in sorted(count_steps, key=lambda x: int(x.get("step") or 0)):
                leg_key = str(s.get("leg_key") or s.get("leg") or "")
                rendered = rendered_count_map.get(leg_key)
                if rendered:
                    available_count.append(rendered)
            combined_filter = " || ".join(f"({flt})" for flt in available_count)

            if not combined_filter and count_steps:
                # If missing only resolved IP, show template expression with placeholder variable.
                unresolved_only = all(
                    (not s.get("available"))
                    and ("rtpengine.resolved_ip" in str(s.get("reason") or ""))
                    for s in count_steps
                )
                if unresolved_only and count_template_map:
                    placeholder_filters: List[str] = []
                    for s in sorted(count_steps, key=lambda x: int(x.get("step") or 0)):
                        leg_key = str(s.get("leg_key") or s.get("leg") or "")
                        expr = count_template_map.get(leg_key)
                        if expr:
                            placeholder_filters.append(expr)
                    if placeholder_filters:
                        combined_filter = " || ".join(f"({flt})" for flt in placeholder_filters)

            print()
            print(f"combined filter: {combined_filter if combined_filter else '<not available>'}")
            print()
            print("Per-leg-filter:")

            if not leg_steps:
                print("<none>")
            else:
                for step in sorted(leg_steps, key=lambda x: int(x.get("step") or 0)):
                    leg_label = str(step.get("leg_key") or step.get("leg") or f"step_{step.get('step')}")
                    rendered = rendered_leg_map.get(leg_label)
                    if rendered:
                        print(f"{leg_label}: {rendered}")
                    else:
                        if "rtpengine.resolved_ip" in str(step.get("reason") or ""):
                            placeholder_expr = leg_template_map.get(leg_label)
                            if placeholder_expr:
                                print(f"{leg_label}: {placeholder_expr}")
                                continue
                        reason = str(step.get("reason") or "not available")
                        print(f"{leg_label}: <unavailable: {reason}>")
        except Exception as filter_exc:
            print(f"⚠️  Could not build filters for selected use case: {filter_exc}")
    else:
        print("❌ No matching use case found")
        print("   This should not happen - check your configuration!")
    
    print("=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze SIP pcap and determine which correlation use case would be selected",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect direction
  %(prog)s capture.pcap
  
  # Force inbound direction
  %(prog)s capture.pcap --direction inbound
  
  # Force outbound direction
  %(prog)s capture.pcap --direction outbound
        """
    )
    
    parser.add_argument(
        "pcap_file",
        help="Path to the SIP pcap file"
    )
    
    parser.add_argument(
        "-d", "--direction",
        choices=["inbound", "outbound"],
        help="Force call direction (auto-detected if not specified)"
    )
    
    args = parser.parse_args()
    
    try:
        analyze_pcap(args.pcap_file, args.direction)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
