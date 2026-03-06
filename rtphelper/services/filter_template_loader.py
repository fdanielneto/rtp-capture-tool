"""
Filter Template Loader

Loads filter templates from YAML files in rtphelper/filter_templates/

Templates define HOW to build tshark filters for RTP capture:
- Filter steps (one per RTP leg)
- Phase 1/2 templates (count/extract phases)
- Required fields for each filter
- Jinja2 template syntax
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
class FilterStep:
    """
    Single filter step definition (one RTP leg).
    
    Each step defines a tshark filter for capturing one direction of RTP flow.
    Example: Carrier → RTP Engine, RTP Engine → Carrier, etc.
    """
    step: int
    leg_name: str
    leg_key: str
    description: str
    phase1_template: str
    phase2_template: str
    required_fields: List[str] = field(default_factory=list)
    field_descriptions: Dict[str, str] = field(default_factory=dict)
    notes: Optional[str] = None
    
    def get_template(self, phase: int = 1) -> str:
        """
        Get template for specific phase.
        
        Args:
            phase: Phase number (1 or 2)
            
        Returns:
            Template string
        """
        if phase == 2:
            return self.phase2_template
        return self.phase1_template
    
    def validate_fields(self, available_fields: List[str]) -> bool:
        """
        Check if all required fields are available.
        
        Args:
            available_fields: List of available field names
            
        Returns:
            True if all required fields are available
        """
        return all(field in available_fields for field in self.required_fields)
    
    def missing_fields(self, available_fields: List[str]) -> List[str]:
        """
        Get list of missing required fields.
        
        Args:
            available_fields: List of available field names
            
        Returns:
            List of missing field names
        """
        return [field for field in self.required_fields if field not in available_fields]


@dataclass
class FilterTemplate:
    """
    Complete filter template definition.
    
    A template defines the tshark filters for a specific topology.
    Examples: direct_2legs, rtp_engine_4legs, sbc_6legs
    """
    name: str
    description: str
    version: str
    topology: str  # Which topology this template is for
    legs: int
    
    # Filter steps (one per RTP leg)
    steps: List[FilterStep] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    required_fields_summary: List[str] = field(default_factory=list)
    field_sources: Dict[str, str] = field(default_factory=dict)
    validation: Dict[str, Any] = field(default_factory=dict)
    annotations: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    
    # Source file
    file_path: Optional[Path] = None
    
    def get_step(self, step_number: int) -> Optional[FilterStep]:
        """
        Get filter step by number.
        
        Args:
            step_number: Step number (1-based)
            
        Returns:
            FilterStep or None if not found
        """
        for step in self.steps:
            if step.step == step_number:
                return step
        return None
    
    def get_steps_for_phase(self, phase: int) -> List[FilterStep]:
        """
        Get all steps for a specific phase.
        
        Args:
            phase: Phase number (1 or 2)
            
        Returns:
            List of FilterStep objects
        """
        return self.steps  # All steps have both phase1 and phase2 templates
    
    def validate_required_fields(self, available_fields: List[str]) -> bool:
        """
        Check if all required fields are available for all steps.
        
        Args:
            available_fields: List of available field names
            
        Returns:
            True if all required fields are available
        """
        for step in self.steps:
            if not step.validate_fields(available_fields):
                return False
        return True
    
    def get_missing_fields(self, available_fields: List[str]) -> Dict[int, List[str]]:
        """
        Get missing fields for each step.
        
        Args:
            available_fields: List of available field names
            
        Returns:
            Dict of step_number -> list of missing field names
        """
        missing = {}
        for step in self.steps:
            missing_fields = step.missing_fields(available_fields)
            if missing_fields:
                missing[step.step] = missing_fields
        return missing


# ═══════════════════════════════════════════════════════════════════════
# LOADER
# ═══════════════════════════════════════════════════════════════════════

class FilterTemplateLoader:
    """
    Load filter templates from YAML files.
    
    Directory structure:
        rtphelper/filter_templates/
        ├── direct_2legs.yaml
        ├── rtp_engine_4legs.yaml
        ├── sbc_6legs.yaml
        └── ...
    
    Usage:
        loader = FilterTemplateLoader()
        templates = loader.load_templates()
        
        template = loader.get_template("rtp_engine_4legs")
        if template:
            for step in template.steps:
                print(f"Step {step.step}: {step.leg_name}")
    """
    
    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialize loader.
        
        Args:
            templates_dir: Optional custom directory path.
                          Defaults to rtphelper/filter_templates/
        """
        if templates_dir is None:
            # Default to rtphelper/filter_templates/
            module_dir = Path(__file__).parent.parent
            templates_dir = module_dir / "filter_templates"
        
        self.templates_dir = Path(templates_dir)
        self.templates: Dict[str, FilterTemplate] = {}
        
        LOGGER.info(f"FilterTemplateLoader initialized: {self.templates_dir}")
    
    def load_templates(self) -> Dict[str, FilterTemplate]:
        """
        Load all filter templates from YAML files.
        
        Returns:
            Dict of template_name -> FilterTemplate
        """
        if not self.templates_dir.exists():
            LOGGER.warning(f"Templates directory not found: {self.templates_dir}")
            return {}
        
        # Find all .yaml and .yml files
        yaml_files = list(self.templates_dir.glob("*.yaml")) + list(self.templates_dir.glob("*.yml"))
        
        if not yaml_files:
            LOGGER.warning(f"No YAML files found in: {self.templates_dir}")
            return {}
        
        # Load each template file
        for yaml_file in yaml_files:
            try:
                template = self._load_template_file(yaml_file)
                if template:
                    self.templates[template.name] = template
                    LOGGER.info(f"✅ Loaded filter template: {template.name} ({len(template.steps)} steps, {template.legs} legs)")
            except Exception as e:
                LOGGER.error(f"❌ Failed to load template from {yaml_file.name}: {e}")
        
        LOGGER.info(f"📦 Loaded {len(self.templates)} filter templates from {self.templates_dir}")
        return self.templates
    
    def _load_template_file(self, file_path: Path) -> Optional[FilterTemplate]:
        """
        Load a single filter template from YAML file.
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            FilterTemplate or None if failed
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            LOGGER.warning(f"Empty YAML file: {file_path}")
            return None
        
        # Parse steps
        steps = []
        for step_data in data.get("steps", []):
            # Clean up multiline templates (remove extra whitespace)
            phase1_template = step_data.get("phase1_template", "").strip()
            phase2_template = step_data.get("phase2_template", "").strip()
            
            step = FilterStep(
                step=step_data.get("step", 0),
                leg_name=step_data.get("leg_name", ""),
                leg_key=step_data.get("leg_key", ""),
                description=step_data.get("description", ""),
                phase1_template=phase1_template,
                phase2_template=phase2_template,
                required_fields=step_data.get("required_fields", []),
                field_descriptions=step_data.get("field_descriptions", {}),
                notes=step_data.get("notes")
            )
            steps.append(step)
        
        # Sort steps by step number
        steps.sort(key=lambda s: s.step)
        
        # Build template object
        template = FilterTemplate(
            name=data.get("name", file_path.stem),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            topology=data.get("topology", ""),
            legs=data.get("legs", len(steps)),
            steps=steps,
            metadata=data.get("metadata", {}),
            required_fields_summary=data.get("required_fields_summary", []),
            field_sources=data.get("field_sources", {}),
            validation=data.get("validation", {}),
            annotations=data.get("annotations", []),
            notes=data.get("notes"),
            file_path=file_path
        )
        
        return template
    
    def get_template(self, name: str) -> Optional[FilterTemplate]:
        """
        Get template by name.
        
        Args:
            name: Template name (e.g., "direct_2legs", "rtp_engine_4legs")
            
        Returns:
            FilterTemplate or None if not found
        """
        return self.templates.get(name)
    
    def get_templates_for_topology(self, topology: str) -> List[FilterTemplate]:
        """
        Get all templates for a specific topology.
        
        Args:
            topology: Topology name (e.g., "direct_topology", "rtp_engine_topology")
            
        Returns:
            List of FilterTemplate objects
        """
        return [t for t in self.templates.values() if t.topology == topology]
    
    def list_templates(self) -> List[str]:
        """
        Get list of loaded template names.
        
        Returns:
            List of template names
        """
        return list(self.templates.keys())
    
    def reload(self) -> Dict[str, FilterTemplate]:
        """
        Reload all templates from disk.
        
        Returns:
            Dict of template_name -> FilterTemplate
        """
        self.templates.clear()
        return self.load_templates()


# ═══════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════

# Global loader instance (lazy loaded)
_global_loader: Optional[FilterTemplateLoader] = None


def get_global_loader() -> FilterTemplateLoader:
    """
    Get global singleton loader instance.
    
    Returns:
        FilterTemplateLoader instance
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = FilterTemplateLoader()
        _global_loader.load_templates()
    return _global_loader


def get_template(name: str) -> Optional[FilterTemplate]:
    """
    Get template by name (convenience function).
    
    Args:
        name: Template name
        
    Returns:
        FilterTemplate or None
    """
    loader = get_global_loader()
    return loader.get_template(name)
