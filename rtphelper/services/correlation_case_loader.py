"""
Dynamic Correlation Case Loader

Loads correlation use case definitions from YAML files in the correlation_cases directory.
Each YAML file defines detection rules and correlation strategy for a specific scenario.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # Handle gracefully if PyYAML not installed

LOGGER = logging.getLogger(__name__)


@dataclass
class HeaderRule:
    """Rule for matching SIP headers."""
    pattern: str
    case_insensitive: bool = True
    required: bool = False


@dataclass
class DetectionRules:
    """Detection rules for a correlation case."""
    direction: str = "both"  # "inbound", "outbound", or "both"
    headers: List[HeaderRule] = field(default_factory=list)
    method: Optional[str] = None  # e.g., "INVITE"


@dataclass
class CorrelationBehaviorConfig:
    """Runtime correlation behavior configuration."""
    # IP extraction sources
    carrier_ip_source: Optional[str] = None  # e.g., "first_invite.src_ip"
    core_ip_source: Optional[str] = None     # e.g., "last_invite.dst_ip"
    
    # Response finding strategy
    response_priority: List[int] = field(default_factory=lambda: [183, 200])  # Try 183 first, then 200
    enable_hop_fallback: bool = True
    enable_adjacent_packet_search: bool = True
    block_xcc_responses: bool = True
    
    # RTP Engine detection
    rtp_engine_detection: str = "enabled"  # "enabled", "disabled", "optional"
    xcc_ip_source: Optional[str] = None     # e.g., "invite_with_changed_sdp.src_ip"
    
    # Special handling
    filter_reinvites: bool = True
    group_multi_call_ids: bool = True


@dataclass
class CorrelationConfig:
    """Correlation configuration for a use case."""
    strategy: str = "generic"  # "generic", "configurable", or class path
    force_direction: Optional[str] = None
    multi_call_id: Optional[bool] = None  # True = multiple Call-IDs, False = single Call-ID
    annotations: List[str] = field(default_factory=list)
    notes: str = ""
    config: Optional[CorrelationBehaviorConfig] = None  # Runtime behavior config


@dataclass
class FilterStepTemplate:
    """Filter template for a single tshark filter step."""
    step: int
    leg_name: str
    leg_key: str
    description: str = ""
    phase1_template: str = ""  # Template for Phase 1 (count)
    phase2_template: str = ""  # Template for Phase 2 (extract)
    required_fields: List[str] = field(default_factory=list)


@dataclass
class FiltersConfig:
    """Filter building configuration."""
    template_set: Optional[str] = None  # "rtp_engine_topology", "direct_topology"
    use_default_templates: bool = True
    custom_templates_enabled: bool = False
    steps: List[FilterStepTemplate] = field(default_factory=list)


@dataclass
class CorrelationCase:
    """Complete definition of a correlation use case."""
    name: str
    description: str
    priority: int = 10
    enabled: bool = True
    detection: DetectionRules = field(default_factory=DetectionRules)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    filters: Optional[FiltersConfig] = None
    file_path: Optional[Path] = None


class CorrelationCaseLoader:
    """
    Loads and manages correlation case definitions from YAML files.
    """
    
    def __init__(self, cases_dir: Optional[Path] = None):
        """
        Initialize the loader.
        
        Args:
            cases_dir: Directory containing YAML case definitions.
                       If not provided, loads from rtphelper/use_cases/
                       with fallback to rtphelper/correlation_cases/.
        """
        if cases_dir is None:
            module_dir = Path(__file__).parent.parent
            self.cases_dirs = [
                module_dir / "use_cases",
                module_dir / "correlation_cases",
            ]
        else:
            self.cases_dirs = [Path(cases_dir)]

        self.cases: List[CorrelationCase] = []
        self._loaded = False
    
    def load_cases(self) -> List[CorrelationCase]:
        """
        Load all correlation cases from YAML files.
        
        Returns:
            List of CorrelationCase objects, sorted by priority (descending)
        """
        if not yaml:
            LOGGER.error("PyYAML not installed - cannot load correlation cases")
            return []
        
        cases_by_name: Dict[str, CorrelationCase] = {}

        for cases_dir in self.cases_dirs:
            if not cases_dir.exists():
                LOGGER.debug(f"Correlation cases directory not found: {cases_dir}")
                continue

            yaml_files = sorted(cases_dir.glob("*.yaml")) + sorted(cases_dir.glob("*.yml"))
            for yaml_file in yaml_files:
                try:
                    case = self._load_case_file(yaml_file)
                    if case and case.enabled:
                        if case.name in cases_by_name:
                            LOGGER.info(
                                "Skipping duplicate use case '%s' from %s (already loaded from %s)",
                                case.name,
                                yaml_file,
                                cases_by_name[case.name].file_path,
                            )
                            continue
                        cases_by_name[case.name] = case
                        LOGGER.debug(f"Loaded correlation case: {case.name} (priority={case.priority})")
                except Exception as e:
                    LOGGER.error(f"Failed to load correlation case from {yaml_file}: {e}")

        if not cases_by_name:
            LOGGER.warning(f"No correlation cases found in directories: {self.cases_dirs}")
            return []

        cases = list(cases_by_name.values())
        
        # Sort by priority (descending)
        cases.sort(key=lambda c: c.priority, reverse=True)
        
        self.cases = cases
        self._loaded = True
        LOGGER.info(f"Loaded {len(cases)} correlation cases from {self.cases_dirs}")
        
        return cases
    
    def _load_case_file(self, file_path: Path) -> Optional[CorrelationCase]:
        """
        Load a single correlation case from a YAML file.
        
        Args:
            file_path: Path to the YAML file
            
        Returns:
            CorrelationCase object or None if invalid
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or not isinstance(data, dict):
            LOGGER.warning(f"Invalid YAML structure in {file_path}")
            return None
        
        # Parse detection rules
        detection_data = data.get("detection", {})
        headers = []
        for header_rule in detection_data.get("headers", []):
            if isinstance(header_rule, dict):
                headers.append(HeaderRule(
                    pattern=header_rule.get("pattern", ""),
                    case_insensitive=header_rule.get("case_insensitive", True),
                    required=header_rule.get("required", False)
                ))
        
        detection = DetectionRules(
            direction=detection_data.get("direction", "both"),
            headers=headers,
            method=detection_data.get("method")
        )
        
        # Parse correlation config
        correlation_data = data.get("correlation", {})
        
        # Parse correlation behavior config (optional)
        behavior_config = None
        if "config" in correlation_data:
            config_data = correlation_data["config"]
            behavior_config = CorrelationBehaviorConfig(
                carrier_ip_source=config_data.get("carrier_ip_source"),
                core_ip_source=config_data.get("core_ip_source"),
                response_priority=config_data.get("response_priority", [183, 200]),
                enable_hop_fallback=config_data.get("enable_hop_fallback", True),
                enable_adjacent_packet_search=config_data.get("enable_adjacent_packet_search", True),
                block_xcc_responses=config_data.get("block_xcc_responses", True),
                rtp_engine_detection=config_data.get("rtp_engine_detection", "enabled"),
                xcc_ip_source=config_data.get("xcc_ip_source"),
                filter_reinvites=config_data.get("filter_reinvites", True),
                group_multi_call_ids=config_data.get("group_multi_call_ids", True),
            )
        
        correlation = CorrelationConfig(
            strategy=correlation_data.get("strategy", "generic"),
            force_direction=correlation_data.get("force_direction"),
            multi_call_id=correlation_data.get("multi_call_id", detection_data.get("multi_call_id")),
            annotations=correlation_data.get("annotations", []),
            notes=correlation_data.get("notes", ""),
            config=behavior_config
        )
        
        # Parse filters config (optional)
        filters_config = None
        if "filters" in data:
            filters_data = data["filters"]
            
            # Parse custom filter steps if present
            custom_steps = []
            if "custom_templates" in filters_data and "steps" in filters_data.get("custom_templates", {}):
                for step_data in filters_data["custom_templates"]["steps"]:
                    custom_steps.append(FilterStepTemplate(
                        step=step_data.get("step", 0),
                        leg_name=step_data.get("leg_name", ""),
                        leg_key=step_data.get("leg_key", ""),
                        description=step_data.get("description", ""),
                        phase1_template=step_data.get("phase1_template", ""),
                        phase2_template=step_data.get("phase2_template", ""),
                        required_fields=step_data.get("required_fields", []),
                    ))
            
            filters_config = FiltersConfig(
                template_set=filters_data.get("template_set") or filters_data.get("template"),
                use_default_templates=filters_data.get("use_default_templates", True),
                custom_templates_enabled=filters_data.get("custom_templates", {}).get("enabled", False)
                or filters_data.get("custom_templates_enabled", False),
                steps=custom_steps
            )
        
        # Build case
        case = CorrelationCase(
            name=data.get("name", file_path.stem),
            description=data.get("description", ""),
            priority=data.get("priority", 10),
            enabled=data.get("enabled", True),
            detection=detection,
            correlation=correlation,
            filters=filters_config,
            file_path=file_path
        )
        
        return case
    
    def get_cases(self) -> List[CorrelationCase]:
        """
        Get loaded cases. Loads them if not already loaded.
        
        Returns:
            List of CorrelationCase objects
        """
        if not self._loaded:
            self.load_cases()
        return self.cases
    
    def reload(self):
        """Reload all cases from disk."""
        self._loaded = False
        self.cases = []
        return self.load_cases()


# Global loader instance
_global_loader: Optional[CorrelationCaseLoader] = None


def get_loader() -> CorrelationCaseLoader:
    """
    Get the global CorrelationCaseLoader instance.
    
    Returns:
        CorrelationCaseLoader instance
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = CorrelationCaseLoader()
        _global_loader.load_cases()
    return _global_loader


def reload_cases():
    """Reload all correlation cases from disk."""
    loader = get_loader()
    return loader.reload()
