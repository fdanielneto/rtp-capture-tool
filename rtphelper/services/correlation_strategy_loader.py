"""
Correlation Strategy Loader

Loads correlation strategies from YAML files in rtphelper/correlation_strategies/

Strategies define HOW to correlate SIP/RTP packets:
- IP extraction (carrier, core, RTP Engine)
- Response finding (183, 200, fallback logic)
- Media extraction (from SDP)
- Topology (2-hop, 3-hop, etc)
- Validation rules
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import logging

LOGGER = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class IpExtractionConfig:
    """Configuration for IP extraction from SIP messages."""
    source: str
    description: Optional[str] = None
    auto_detect_direction: bool = True
    fallback_source: Optional[str] = None
    
    # Optional direction-specific sources
    inbound_source: Optional[str] = None
    outbound_source: Optional[str] = None


@dataclass
class ResponseFindingConfig:
    """Configuration for finding SIP responses for media extraction."""
    response_priority: List[int] = field(default_factory=lambda: [183, 200])
    enable_hop_fallback: bool = True
    enable_adjacent_packet_search: bool = True
    block_xcc_responses: bool = False
    description: Optional[str] = None


@dataclass
class MediaExtractionConfig:
    """Configuration for media extraction from SDP."""
    mode: str = "sdp_from_responses"
    extract_from: List[Dict[str, Any]] = field(default_factory=list)
    phases: List[Dict[str, Any]] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class RtpEngineDetectionConfig:
    """Configuration for RTP Engine detection."""
    enabled: bool = False
    detection_method: Optional[str] = None
    xcc_ip_source: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ReinviteFilteringConfig:
    """Configuration for Re-INVITE handling."""
    enabled: bool = True
    description: Optional[str] = None


@dataclass
class ValidationConfig:
    """Configuration for validation rules."""
    required_ips: List[str] = field(default_factory=list)
    required_rtp_endpoints: List[str] = field(default_factory=list)
    minimum_packets: int = 10
    description: Optional[str] = None


@dataclass
class TopologyConfig:
    """Configuration for call topology."""
    legs: int = 2
    description: Optional[str] = None
    phases: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class CorrelationStrategy:
    """
    Complete correlation strategy definition.
    
    A strategy defines HOW to correlate SIP/RTP packets for a specific topology.
    Examples: direct_topology, rtp_engine_topology, sbc_topology
    """
    name: str
    description: str
    version: str
    topology_type: str
    hops: int
    
    # Configuration sections
    ip_extraction: Dict[str, IpExtractionConfig]
    response_finding: ResponseFindingConfig
    media_extraction: MediaExtractionConfig
    topology: TopologyConfig
    rtp_engine_detection: RtpEngineDetectionConfig
    reinvite_filtering: ReinviteFilteringConfig
    validation: ValidationConfig
    
    # Metadata
    overridable: List[str] = field(default_factory=list)
    legacy_mapping: Dict[str, str] = field(default_factory=dict)
    annotations: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    
    # Source file
    file_path: Optional[Path] = None
    
    def get_ip_source(self, ip_type: str, direction: Optional[str] = None) -> Optional[str]:
        """
        Get IP extraction source for a specific IP type and direction.
        
        Args:
            ip_type: Type of IP (carrier, core, rtp_engine, etc)
            direction: Optional direction (inbound, outbound)
            
        Returns:
            Source string or None if not found
        """
        ip_config = self.ip_extraction.get(ip_type)
        if not ip_config:
            return None
        
        # Check direction-specific sources
        if direction == "inbound" and ip_config.inbound_source:
            return ip_config.inbound_source
        
        if direction == "outbound" and ip_config.outbound_source:
            return ip_config.outbound_source
        
        # Use default source
        return ip_config.source
    
    def get_legacy_field(self, legacy_field_name: str) -> Any:
        """
        Get value from legacy field mapping for backward compatibility.
        
        Args:
            legacy_field_name: Legacy field name (e.g., carrier_ip_source)
            
        Returns:
            Value or None if not mapped
        """
        new_field_path = self.legacy_mapping.get(legacy_field_name)
        if not new_field_path:
            return None
        
        # Navigate nested structure (e.g., ip_extraction.carrier.source)
        parts = new_field_path.split(".")
        value = self
        
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            elif isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        
        return value


# ═══════════════════════════════════════════════════════════════════════
# LOADER
# ═══════════════════════════════════════════════════════════════════════

class CorrelationStrategyLoader:
    """
    Load correlation strategies from YAML files.
    
    Directory structure:
        rtphelper/correlation_strategies/
        ├── direct_topology.yaml
        ├── rtp_engine_topology.yaml
        ├── sbc_topology.yaml
        └── ...
    
    Usage:
        loader = CorrelationStrategyLoader()
        strategies = loader.load_strategies()
        
        strategy = loader.get_strategy("rtp_engine_topology")
        if strategy:
            carrier_ip_source = strategy.get_ip_source("carrier", "inbound")
    """
    
    def __init__(self, strategies_dir: Optional[Path] = None):
        """
        Initialize loader.
        
        Args:
            strategies_dir: Optional custom directory path.
                           Defaults to rtphelper/correlation_strategies/
        """
        if strategies_dir is None:
            # Default to rtphelper/correlation_strategies/
            module_dir = Path(__file__).parent.parent
            strategies_dir = module_dir / "correlation_strategies"
        
        self.strategies_dir = Path(strategies_dir)
        self.strategies: Dict[str, CorrelationStrategy] = {}
        
        LOGGER.info(f"CorrelationStrategyLoader initialized: {self.strategies_dir}")
    
    def load_strategies(self) -> Dict[str, CorrelationStrategy]:
        """
        Load all correlation strategies from YAML files.
        
        Returns:
            Dict of strategy_name -> CorrelationStrategy
        """
        if not self.strategies_dir.exists():
            LOGGER.warning(f"Strategies directory not found: {self.strategies_dir}")
            return {}
        
        # Find all .yaml and .yml files
        yaml_files = list(self.strategies_dir.glob("*.yaml")) + list(self.strategies_dir.glob("*.yml"))
        
        if not yaml_files:
            LOGGER.warning(f"No YAML files found in: {self.strategies_dir}")
            return {}
        
        # Load each strategy file
        for yaml_file in yaml_files:
            try:
                strategy = self._load_strategy_file(yaml_file)
                if strategy:
                    self.strategies[strategy.name] = strategy
                    LOGGER.info(f"✅ Loaded strategy: {strategy.name} (version {strategy.version}, {strategy.hops}-hop)")
            except Exception as e:
                LOGGER.error(f"❌ Failed to load strategy from {yaml_file.name}: {e}")
        
        LOGGER.info(f"📦 Loaded {len(self.strategies)} correlation strategies from {self.strategies_dir}")
        return self.strategies
    
    def _load_strategy_file(self, file_path: Path) -> Optional[CorrelationStrategy]:
        """
        Load a single strategy from YAML file.
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            CorrelationStrategy or None if failed
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            LOGGER.warning(f"Empty YAML file: {file_path}")
            return None
        
        # Parse IP extraction configs
        ip_extraction = {}
        for key, value in data.get("ip_extraction", {}).items():
            if isinstance(value, dict):
                ip_extraction[key] = IpExtractionConfig(
                    source=value.get("source", ""),
                    description=value.get("description"),
                    auto_detect_direction=value.get("auto_detect_direction", True),
                    fallback_source=value.get("fallback_source") or value.get("fallback"),
                    inbound_source=value.get("inbound_source"),
                    outbound_source=value.get("outbound_source")
                )
            else:
                # Simple string value
                ip_extraction[key] = IpExtractionConfig(source=str(value))
        
        # Parse response finding
        response_finding_data = data.get("response_finding", {})
        response_finding = ResponseFindingConfig(
            response_priority=response_finding_data.get("response_priority", [183, 200]),
            enable_hop_fallback=response_finding_data.get("enable_hop_fallback", True),
            enable_adjacent_packet_search=response_finding_data.get("enable_adjacent_packet_search", True),
            block_xcc_responses=response_finding_data.get("block_xcc_responses", False),
            description=response_finding_data.get("description")
        )
        
        # Parse media extraction
        media_extraction_data = data.get("media_extraction", {})
        media_extraction = MediaExtractionConfig(
            mode=media_extraction_data.get("mode", "sdp_from_responses"),
            extract_from=media_extraction_data.get("extract_from", []),
            phases=media_extraction_data.get("phases", []),
            description=media_extraction_data.get("description")
        )
        
        # Parse topology
        topology_data = data.get("topology", {})
        topology = TopologyConfig(
            legs=topology_data.get("legs", 2),
            description=topology_data.get("description"),
            phases=topology_data.get("phases", [])
        )
        
        # Parse RTP Engine detection
        rtp_engine_data = data.get("rtp_engine_detection", {})
        rtp_engine_detection = RtpEngineDetectionConfig(
            enabled=rtp_engine_data.get("enabled", False),
            detection_method=rtp_engine_data.get("detection_method"),
            xcc_ip_source=rtp_engine_data.get("xcc_ip_source"),
            description=rtp_engine_data.get("description")
        )
        
        # Parse Re-INVITE filtering
        reinvite_data = data.get("reinvite_filtering", {})
        reinvite_filtering = ReinviteFilteringConfig(
            enabled=reinvite_data.get("enabled", True),
            description=reinvite_data.get("description")
        )
        
        # Parse validation
        validation_data = data.get("validation", {})
        validation = ValidationConfig(
            required_ips=validation_data.get("required_ips", []),
            required_rtp_endpoints=validation_data.get("required_rtp_endpoints", []),
            minimum_packets=validation_data.get("minimum_packets", 10),
            description=validation_data.get("description")
        )
        
        # Build strategy object
        strategy = CorrelationStrategy(
            name=data.get("name", file_path.stem),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            topology_type=data.get("topology_type", "unknown"),
            hops=data.get("hops", 2),
            ip_extraction=ip_extraction,
            response_finding=response_finding,
            media_extraction=media_extraction,
            topology=topology,
            rtp_engine_detection=rtp_engine_detection,
            reinvite_filtering=reinvite_filtering,
            validation=validation,
            overridable=data.get("overridable", []),
            legacy_mapping=data.get("legacy_mapping", {}),
            annotations=data.get("annotations", []),
            notes=data.get("notes"),
            file_path=file_path
        )
        
        return strategy
    
    def get_strategy(self, name: str) -> Optional[CorrelationStrategy]:
        """
        Get strategy by name.
        
        Args:
            name: Strategy name (e.g., "direct_topology", "rtp_engine_topology")
            
        Returns:
            CorrelationStrategy or None if not found
        """
        return self.strategies.get(name)
    
    def list_strategies(self) -> List[str]:
        """
        Get list of loaded strategy names.
        
        Returns:
            List of strategy names
        """
        return list(self.strategies.keys())
    
    def reload(self) -> Dict[str, CorrelationStrategy]:
        """
        Reload all strategies from disk.
        
        Returns:
            Dict of strategy_name -> CorrelationStrategy
        """
        self.strategies.clear()
        return self.load_strategies()


# ═══════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════

# Global loader instance (lazy loaded)
_global_loader: Optional[CorrelationStrategyLoader] = None


def get_global_loader() -> CorrelationStrategyLoader:
    """
    Get global singleton loader instance.
    
    Returns:
        CorrelationStrategyLoader instance
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = CorrelationStrategyLoader()
        _global_loader.load_strategies()
    return _global_loader


def get_strategy(name: str) -> Optional[CorrelationStrategy]:
    """
    Get strategy by name (convenience function).
    
    Args:
        name: Strategy name
        
    Returns:
        CorrelationStrategy or None
    """
    loader = get_global_loader()
    return loader.get_strategy(name)
