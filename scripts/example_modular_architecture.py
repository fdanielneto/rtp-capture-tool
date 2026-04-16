#!/usr/bin/env python3
"""
Example implementation of the new modular YAML architecture.

This script demonstrates:
1. Loading correlation strategies from YAML files
2. Loading filter templates from YAML files
3. Using strategies in ConfigurableCorrelator
4. Building filters from templates
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import logging

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class IpExtractionConfig:
    """Configuration for IP extraction."""
    source: str
    fallback: Optional[str] = None
    inbound_source: Optional[str] = None
    outbound_source: Optional[str] = None


@dataclass
class ResponseFindingConfig:
    """Configuration for response finding."""
    priority: List[int] = field(default_factory=lambda: [200, 183])
    enable_hop_fallback: bool = True
    enable_adjacent_packet_search: bool = True
    block_xcc_responses: bool = False


@dataclass
class MediaExtractionConfig:
    """Configuration for media extraction."""
    filter_reinvites: bool = True
    prefer_early_media: bool = False


@dataclass
class TopologyLeg:
    """Definition of a topology leg."""
    name: str
    source: str
    destination: str


@dataclass
class TopologyConfig:
    """Configuration for topology."""
    type: str  # two_hop, three_hop, etc.
    legs: List[TopologyLeg] = field(default_factory=list)


@dataclass
class ValidationConfig:
    """Configuration for validation."""
    require_rtp_engine: bool = False
    min_invites: int = 1
    max_invites: int = 5
    require_responses: bool = True


@dataclass
class CorrelationStrategy:
    """Complete correlation strategy definition."""
    name: str
    description: str
    version: str
    ip_extraction: Dict[str, IpExtractionConfig]
    response_finding: ResponseFindingConfig
    media_extraction: MediaExtractionConfig
    topology: TopologyConfig
    validation: ValidationConfig
    file_path: Optional[Path] = None


@dataclass
class FilterStep:
    """Single filter step definition."""
    step: int
    leg_name: str
    leg_key: str
    description: str
    phase1_template: str
    phase2_template: str
    required_fields: List[str] = field(default_factory=list)


@dataclass
class FilterTemplate:
    """Complete filter template definition."""
    name: str
    description: str
    version: str
    topology: str  # Which topology this template is for
    steps: List[FilterStep]
    file_path: Optional[Path] = None


@dataclass
class MultiCallIdConfig:
    """Multi Call-ID grouping configuration."""
    enabled: bool = False
    grouping_header: Optional[str] = None
    grouping_headers: List[str] = field(default_factory=list)


@dataclass
class CorrelationCase:
    """Use case definition (simplified)."""
    name: str
    description: str
    priority: int
    enabled: bool
    detection: Dict
    correlation_strategy: str  # Reference to strategy file
    correlation_overrides: Dict = field(default_factory=dict)
    multi_call_id: Optional[MultiCallIdConfig] = None
    filter_template: str  # Reference to filter template file
    custom_templates_enabled: bool = False
    custom_steps: List[FilterStep] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
# LOADERS
# ═══════════════════════════════════════════════════════════════════════

class CorrelationStrategyLoader:
    """
    Load correlation strategies from YAML files.
    
    Directory structure:
        rtphelper/correlation_strategies/
        ├── direct_topology.yaml
        ├── rtp_engine_topology.yaml
        └── sbc_topology.yaml
    """
    
    def __init__(self, strategies_dir: Optional[Path] = None):
        if strategies_dir is None:
            module_dir = Path(__file__).parent.parent
            strategies_dir = module_dir / "rtphelper" / "correlation_strategies"
        
        self.strategies_dir = Path(strategies_dir)
        self.strategies: Dict[str, CorrelationStrategy] = {}
    
    def load_strategies(self) -> Dict[str, CorrelationStrategy]:
        """Load all correlation strategies from YAML files."""
        if not self.strategies_dir.exists():
            LOGGER.warning(f"Strategies directory not found: {self.strategies_dir}")
            return {}
        
        yaml_files = list(self.strategies_dir.glob("*.yaml")) + list(self.strategies_dir.glob("*.yml"))
        
        for yaml_file in yaml_files:
            try:
                strategy = self._load_strategy_file(yaml_file)
                if strategy:
                    self.strategies[strategy.name] = strategy
                    LOGGER.info(f"Loaded strategy: {strategy.name} (version {strategy.version})")
            except Exception as e:
                LOGGER.error(f"Failed to load strategy from {yaml_file}: {e}")
        
        LOGGER.info(f"Loaded {len(self.strategies)} correlation strategies")
        return self.strategies
    
    def _load_strategy_file(self, file_path: Path) -> Optional[CorrelationStrategy]:
        """Load a single strategy from YAML file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return None
        
        # Parse IP extraction
        ip_extraction = {}
        for key, value in data.get("ip_extraction", {}).items():
            if isinstance(value, dict):
                ip_extraction[key] = IpExtractionConfig(**value)
            else:
                ip_extraction[key] = IpExtractionConfig(source=value)
        
        # Parse response finding
        response_finding_data = data.get("response_finding", {})
        response_finding = ResponseFindingConfig(**response_finding_data)
        
        # Parse media extraction
        media_extraction_data = data.get("media_extraction", {})
        media_extraction = MediaExtractionConfig(**media_extraction_data)
        
        # Parse topology
        topology_data = data.get("topology", {})
        topology_legs = []
        for leg_data in topology_data.get("legs", []):
            topology_legs.append(TopologyLeg(**leg_data))
        
        topology = TopologyConfig(
            type=topology_data.get("type", "unknown"),
            legs=topology_legs
        )
        
        # Parse validation
        validation_data = data.get("validation", {})
        validation = ValidationConfig(**validation_data)
        
        # Build strategy
        strategy = CorrelationStrategy(
            name=data.get("name", file_path.stem),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            ip_extraction=ip_extraction,
            response_finding=response_finding,
            media_extraction=media_extraction,
            topology=topology,
            validation=validation,
            file_path=file_path
        )
        
        return strategy
    
    def get_strategy(self, name: str) -> Optional[CorrelationStrategy]:
        """Get strategy by name."""
        return self.strategies.get(name)


class FilterTemplateLoader:
    """
    Load filter templates from YAML files.
    
    Directory structure:
        rtphelper/filter_templates/
        ├── direct_2legs.yaml
        ├── rtp_engine_4legs.yaml
        └── sbc_6legs.yaml
    """
    
    def __init__(self, templates_dir: Optional[Path] = None):
        if templates_dir is None:
            module_dir = Path(__file__).parent.parent
            templates_dir = module_dir / "rtphelper" / "filter_templates"
        
        self.templates_dir = Path(templates_dir)
        self.templates: Dict[str, FilterTemplate] = {}
    
    def load_templates(self) -> Dict[str, FilterTemplate]:
        """Load all filter templates from YAML files."""
        if not self.templates_dir.exists():
            LOGGER.warning(f"Templates directory not found: {self.templates_dir}")
            return {}
        
        yaml_files = list(self.templates_dir.glob("*.yaml")) + list(self.templates_dir.glob("*.yml"))
        
        for yaml_file in yaml_files:
            try:
                template = self._load_template_file(yaml_file)
                if template:
                    self.templates[template.name] = template
                    LOGGER.info(f"Loaded filter template: {template.name} ({len(template.steps)} steps)")
            except Exception as e:
                LOGGER.error(f"Failed to load template from {yaml_file}: {e}")
        
        LOGGER.info(f"Loaded {len(self.templates)} filter templates")
        return self.templates
    
    def _load_template_file(self, file_path: Path) -> Optional[FilterTemplate]:
        """Load a single filter template from YAML file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return None
        
        # Parse steps
        steps = []
        for step_data in data.get("steps", []):
            steps.append(FilterStep(
                step=step_data.get("step", 0),
                leg_name=step_data.get("leg_name", ""),
                leg_key=step_data.get("leg_key", ""),
                description=step_data.get("description", ""),
                phase1_template=step_data.get("phase1_template", ""),
                phase2_template=step_data.get("phase2_template", ""),
                required_fields=step_data.get("required_fields", [])
            ))
        
        # Build template
        template = FilterTemplate(
            name=data.get("name", file_path.stem),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            topology=data.get("topology", ""),
            steps=steps,
            file_path=file_path
        )
        
        return template
    
    def get_template(self, name: str) -> Optional[FilterTemplate]:
        """Get template by name."""
        return self.templates.get(name)


class CorrelationCaseLoader:
    """
    Load correlation cases (use cases) from YAML files.
    
    Directory structure:
        rtphelper/correlation_cases/
        ├── inbound_direct.yaml
        ├── inbound_rtp_engine.yaml
        └── ...
    """
    
    def __init__(self, cases_dir: Optional[Path] = None):
        if cases_dir is None:
            module_dir = Path(__file__).parent.parent
            cases_dir = module_dir / "rtphelper" / "correlation_cases"
        
        self.cases_dir = Path(cases_dir)
        self.cases: List[CorrelationCase] = []
    
    def load_cases(self) -> List[CorrelationCase]:
        """Load all correlation cases from YAML files."""
        if not self.cases_dir.exists():
            LOGGER.warning(f"Cases directory not found: {self.cases_dir}")
            return []
        
        yaml_files = list(self.cases_dir.glob("*.yaml")) + list(self.cases_dir.glob("*.yml"))
        
        for yaml_file in yaml_files:
            try:
                case = self._load_case_file(yaml_file)
                if case and case.enabled:
                    self.cases.append(case)
                    LOGGER.info(f"Loaded use case: {case.name} (priority={case.priority}, strategy={case.correlation_strategy})")
            except Exception as e:
                LOGGER.error(f"Failed to load case from {yaml_file}: {e}")
        
        # Sort by priority (descending)
        self.cases.sort(key=lambda c: c.priority, reverse=True)
        
        LOGGER.info(f"Loaded {len(self.cases)} correlation cases")
        return self.cases
    
    def _load_case_file(self, file_path: Path) -> Optional[CorrelationCase]:
        """Load a single correlation case from YAML file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return None
        
        # Parse multi_call_id config
        multi_call_id = None
        if "correlation" in data and "multi_call_id" in data["correlation"]:
            multi_call_id_data = data["correlation"]["multi_call_id"]
            multi_call_id = MultiCallIdConfig(**multi_call_id_data)
        
        # Parse custom filter steps if present
        custom_steps = []
        filters_data = data.get("filters", {})
        if filters_data.get("custom_templates_enabled") and "custom_steps" in filters_data:
            for step_data in filters_data["custom_steps"]:
                custom_steps.append(FilterStep(**step_data))
        
        # Build case
        case = CorrelationCase(
            name=data.get("name", file_path.stem),
            description=data.get("description", ""),
            priority=data.get("priority", 10),
            enabled=data.get("enabled", True),
            detection=data.get("detection", {}),
            correlation_strategy=data.get("correlation", {}).get("strategy", "generic"),
            correlation_overrides=data.get("correlation", {}).get("overrides", {}),
            multi_call_id=multi_call_id,
            filter_template=filters_data.get("template", ""),
            custom_templates_enabled=filters_data.get("custom_templates_enabled", False),
            custom_steps=custom_steps
        )
        
        return case


# ═══════════════════════════════════════════════════════════════════════
# EXAMPLE USAGE
# ═══════════════════════════════════════════════════════════════════════

def main():
    """Example usage of the new modular architecture."""
    
    print("=" * 80)
    print("NEW MODULAR YAML ARCHITECTURE - EXAMPLE")
    print("=" * 80)
    print()
    
    # ─────────────────────────────────────────────────────────────────
    # 1. Load Correlation Strategies
    # ─────────────────────────────────────────────────────────────────
    print("1. Loading Correlation Strategies...")
    print("-" * 80)
    
    strategy_loader = CorrelationStrategyLoader()
    strategies = strategy_loader.load_strategies()
    
    print(f"\n✅ Loaded {len(strategies)} strategies:")
    for name, strategy in strategies.items():
        print(f"   • {name} (v{strategy.version})")
        print(f"     - Topology: {strategy.topology.type}")
        print(f"     - Legs: {len(strategy.topology.legs)}")
        print(f"     - RTP Engine: {strategy.validation.require_rtp_engine}")
    
    print()
    
    # ─────────────────────────────────────────────────────────────────
    # 2. Load Filter Templates
    # ─────────────────────────────────────────────────────────────────
    print("2. Loading Filter Templates...")
    print("-" * 80)
    
    template_loader = FilterTemplateLoader()
    templates = template_loader.load_templates()
    
    print(f"\n✅ Loaded {len(templates)} filter templates:")
    for name, template in templates.items():
        print(f"   • {name} (v{template.version})")
        print(f"     - Topology: {template.topology}")
        print(f"     - Steps: {len(template.steps)}")
        for step in template.steps:
            print(f"       {step.step}. {step.leg_name}")
    
    print()
    
    # ─────────────────────────────────────────────────────────────────
    # 3. Load Correlation Cases (Use Cases)
    # ─────────────────────────────────────────────────────────────────
    print("3. Loading Correlation Cases (Use Cases)...")
    print("-" * 80)
    
    case_loader = CorrelationCaseLoader()
    cases = case_loader.load_cases()
    
    print(f"\n✅ Loaded {len(cases)} use cases (sorted by priority):")
    for case in cases:
        multi_cid = "Multi CID" if case.multi_call_id and case.multi_call_id.enabled else "Single CID"
        print(f"   [{case.priority:3d}] {case.name}")
        print(f"        Strategy:  {case.correlation_strategy}")
        print(f"        Filters:   {case.filter_template}")
        print(f"        Call-IDs:  {multi_cid}")
        if case.multi_call_id and case.multi_call_id.enabled:
            print(f"        Grouping:  {case.multi_call_id.grouping_header}")
    
    print()
    
    # ─────────────────────────────────────────────────────────────────
    # 4. Example: Get Strategy Details
    # ─────────────────────────────────────────────────────────────────
    print("4. Example: Get Strategy Details")
    print("-" * 80)
    
    strategy = strategy_loader.get_strategy("rtp_engine_topology")
    if strategy:
        print(f"\nStrategy: {strategy.name}")
        print(f"Description: {strategy.description}")
        print(f"\nIP Extraction:")
        for key, config in strategy.ip_extraction.items():
            print(f"  • {key}: {config.source}")
        
        print(f"\nResponse Finding:")
        print(f"  • Priority: {strategy.response_finding.priority}")
        print(f"  • Block XCC: {strategy.response_finding.block_xcc_responses}")
        
        print(f"\nTopology:")
        print(f"  • Type: {strategy.topology.type}")
        for leg in strategy.topology.legs:
            print(f"  • {leg.name}: {leg.source} → {leg.destination}")
    
    print()
    
    # ─────────────────────────────────────────────────────────────────
    # 5. Example: Get Filter Template Details
    # ─────────────────────────────────────────────────────────────────
    print("5. Example: Get Filter Template Details")
    print("-" * 80)
    
    template = template_loader.get_template("rtp_engine_4legs")
    if template:
        print(f"\nTemplate: {template.name}")
        print(f"Description: {template.description}")
        print(f"Steps: {len(template.steps)}")
        
        for step in template.steps:
            print(f"\n  Step {step.step}: {step.leg_name}")
            print(f"    Description: {step.description}")
            print(f"    Required fields: {', '.join(step.required_fields)}")
            print(f"    Template: {step.phase1_template[:60]}...")
    
    print()
    
    # ─────────────────────────────────────────────────────────────────
    # 6. Example: Strategy Reusage
    # ─────────────────────────────────────────────────────────────────
    print("6. Example: Strategy Reusage")
    print("-" * 80)
    
    print("\nCases using 'rtp_engine_topology' strategy:")
    rtp_engine_cases = [c for c in cases if c.correlation_strategy == "rtp_engine_topology"]
    for case in rtp_engine_cases:
        print(f"  • {case.name} (priority {case.priority})")
    
    print(f"\n✅ 1 strategy → {len(rtp_engine_cases)} use cases")
    
    print("\nCases using 'direct_topology' strategy:")
    direct_cases = [c for c in cases if c.correlation_strategy == "direct_topology"]
    for case in direct_cases:
        print(f"  • {case.name} (priority {case.priority})")
    
    print(f"\n✅ 1 strategy → {len(direct_cases)} use cases")
    
    print()
    print("=" * 80)
    print("✅ NEW MODULAR ARCHITECTURE DEMONSTRATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
