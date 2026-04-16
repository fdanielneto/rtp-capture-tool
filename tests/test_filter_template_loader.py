"""
Unit tests for Filter Template Loader

Tests the loading and parsing of filter templates from YAML files.
"""

import pytest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.filter_template_loader import (
    FilterTemplateLoader,
    FilterTemplate,
    FilterStep,
    get_template,
)


class TestFilterTemplateLoader:
    """Test suite for FilterTemplateLoader."""
    
    def test_loader_initialization(self):
        """Test that loader initializes correctly."""
        loader = FilterTemplateLoader()
        assert loader is not None
        assert loader.templates_dir.exists()
    
    def test_load_templates(self):
        """Test loading all templates from directory."""
        loader = FilterTemplateLoader()
        templates = loader.load_templates()
        
        assert isinstance(templates, dict)
        assert len(templates) >= 2  # At least direct_2legs and rtp_engine_4legs
        
        # Check that expected templates are loaded
        assert "direct_2legs" in templates
        assert "rtp_engine_4legs" in templates
    
    def test_direct_2legs_structure(self):
        """Test that direct_2legs template has correct structure."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("direct_2legs")
        assert template is not None
        
        # Check basic fields
        assert template.name == "direct_2legs"
        assert template.legs == 2
        assert template.topology == "direct_topology"
        
        # Check steps
        assert len(template.steps) == 2
        
        # Check step 1
        step1 = template.get_step(1)
        assert step1 is not None
        assert step1.leg_name == "carrier->core"
        assert step1.leg_key == "leg_carrier_core"
        assert "carrier.source.ip" in step1.required_fields
        assert "carrier.source.port" in step1.required_fields
        
        # Check templates are present
        assert step1.phase1_template
        assert step1.phase2_template
        assert "ip.src==" in step1.phase1_template
        assert "udp.srcport==" in step1.phase1_template
        
        # Check step 2
        step2 = template.get_step(2)
        assert step2 is not None
        assert step2.leg_name == "core->carrier"
        assert step2.leg_key == "leg_core_carrier"
        assert "core.destination.ip" in step2.required_fields
        assert "core.destination.port" in step2.required_fields
    
    def test_rtp_engine_4legs_structure(self):
        """Test that rtp_engine_4legs template has correct structure."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("rtp_engine_4legs")
        assert template is not None
        
        # Check basic fields
        assert template.name == "rtp_engine_4legs"
        assert template.legs == 4
        assert template.topology == "rtp_engine_topology"
        
        # Check steps
        assert len(template.steps) == 4
        
        # Check all steps are present
        for step_num in [1, 2, 3, 4]:
            step = template.get_step(step_num)
            assert step is not None
            assert step.step == step_num
            assert step.phase1_template
            assert step.phase2_template
    
    def test_filter_step_get_template(self):
        """Test FilterStep.get_template() method."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("direct_2legs")
        step = template.get_step(1)
        
        # Get phase 1 template
        phase1 = step.get_template(phase=1)
        assert phase1 == step.phase1_template
        
        # Get phase 2 template
        phase2 = step.get_template(phase=2)
        assert phase2 == step.phase2_template
    
    def test_filter_step_validate_fields(self):
        """Test FilterStep.validate_fields() method."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("direct_2legs")
        step = template.get_step(1)
        
        # All fields available
        available_fields = ["carrier.source.ip", "carrier.source.port", "core.destination.ip"]
        assert step.validate_fields(available_fields) is True
        
        # Missing field
        incomplete_fields = ["carrier.source.ip"]  # Missing carrier.source.port
        assert step.validate_fields(incomplete_fields) is False
    
    def test_filter_step_missing_fields(self):
        """Test FilterStep.missing_fields() method."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("direct_2legs")
        step = template.get_step(1)
        
        # Some fields available
        available_fields = ["carrier.source.ip"]
        missing = step.missing_fields(available_fields)
        
        assert "carrier.source.port" in missing
        assert "carrier.source.ip" not in missing
    
    def test_template_validate_required_fields(self):
        """Test FilterTemplate.validate_required_fields() method."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("direct_2legs")
        
        # All fields available
        all_fields = [
            "carrier.source.ip",
            "carrier.source.port",
            "core.destination.ip",
            "core.destination.port"
        ]
        assert template.validate_required_fields(all_fields) is True
        
        # Missing some fields
        incomplete_fields = ["carrier.source.ip", "carrier.source.port"]
        assert template.validate_required_fields(incomplete_fields) is False
    
    def test_template_get_missing_fields(self):
        """Test FilterTemplate.get_missing_fields() method."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template = loader.get_template("direct_2legs")
        
        # Partial fields
        available_fields = ["carrier.source.ip", "carrier.source.port"]
        missing = template.get_missing_fields(available_fields)
        
        # Step 1 should be OK (has carrier fields)
        assert 1 not in missing
        
        # Step 2 should be missing core fields
        assert 2 in missing
        assert "core.destination.ip" in missing[2]
        assert "core.destination.port" in missing[2]
    
    def test_get_templates_for_topology(self):
        """Test getting templates by topology."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        # Get direct topology templates
        direct_templates = loader.get_templates_for_topology("direct_topology")
        assert len(direct_templates) >= 1
        assert any(t.name == "direct_2legs" for t in direct_templates)
        
        # Get rtp_engine topology templates
        rtp_templates = loader.get_templates_for_topology("rtp_engine_topology")
        assert len(rtp_templates) >= 1
        assert any(t.name == "rtp_engine_4legs" for t in rtp_templates)
    
    def test_get_template_function(self):
        """Test convenience function get_template()."""
        template = get_template("direct_2legs")
        assert template is not None
        assert template.name == "direct_2legs"
    
    def test_list_templates(self):
        """Test listing all loaded template names."""
        loader = FilterTemplateLoader()
        loader.load_templates()
        
        template_names = loader.list_templates()
        assert isinstance(template_names, list)
        assert len(template_names) >= 2
        assert "direct_2legs" in template_names
        assert "rtp_engine_4legs" in template_names
    
    def test_reload_templates(self):
        """Test reloading templates from disk."""
        loader = FilterTemplateLoader()
        templates1 = loader.load_templates()
        
        # Reload
        templates2 = loader.reload()
        
        assert len(templates1) == len(templates2)
        assert set(templates1.keys()) == set(templates2.keys())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
