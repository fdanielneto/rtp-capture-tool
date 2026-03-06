"""
Unit tests for Correlation Strategy Loader

Tests the loading and parsing of correlation strategies from YAML files.
"""

import pytest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.correlation_strategy_loader import (
    CorrelationStrategyLoader,
    CorrelationStrategy,
    get_strategy,
)


class TestCorrelationStrategyLoader:
    """Test suite for CorrelationStrategyLoader."""
    
    def test_loader_initialization(self):
        """Test that loader initializes correctly."""
        loader = CorrelationStrategyLoader()
        assert loader is not None
        assert loader.strategies_dir.exists()
    
    def test_load_strategies(self):
        """Test loading all strategies from directory."""
        loader = CorrelationStrategyLoader()
        strategies = loader.load_strategies()
        
        assert isinstance(strategies, dict)
        assert len(strategies) >= 2  # At least direct_topology and rtp_engine_topology
        
        # Check that expected strategies are loaded
        assert "direct_topology" in strategies
        assert "rtp_engine_topology" in strategies
    
    def test_direct_topology_structure(self):
        """Test that direct_topology strategy has correct structure."""
        loader = CorrelationStrategyLoader()
        loader.load_strategies()
        
        strategy = loader.get_strategy("direct_topology")
        assert strategy is not None
        
        # Check basic fields
        assert strategy.name == "direct_topology"
        assert strategy.hops == 2
        assert strategy.topology_type == "direct_media"
        
        # Check IP extraction
        assert "carrier" in strategy.ip_extraction
        assert "core" in strategy.ip_extraction
        assert strategy.ip_extraction["carrier"].source == "first_invite.src_ip"
        assert strategy.ip_extraction["core"].source == "last_invite.dst_ip"
        
        # Check response finding
        assert strategy.response_finding.response_priority == [183, 200]
        assert strategy.response_finding.enable_hop_fallback is True
        
        # Check topology
        assert strategy.topology.legs == 2
        
        # Check RTP Engine detection (should be disabled for direct)
        assert strategy.rtp_engine_detection.enabled is False
        
        # Check validation
        assert "carrier" in strategy.validation.required_ips
        assert "core" in strategy.validation.required_ips
    
    def test_rtp_engine_topology_structure(self):
        """Test that rtp_engine_topology strategy has correct structure."""
        loader = CorrelationStrategyLoader()
        loader.load_strategies()
        
        strategy = loader.get_strategy("rtp_engine_topology")
        assert strategy is not None
        
        # Check basic fields
        assert strategy.name == "rtp_engine_topology"
        assert strategy.hops == 3
        assert strategy.topology_type == "rtp_engine_media_proxy"
        
        # Check IP extraction
        assert "carrier" in strategy.ip_extraction
        assert "core" in strategy.ip_extraction
        assert "rtp_engine" in strategy.ip_extraction
        assert strategy.ip_extraction["rtp_engine"].source == "invite_with_changed_sdp.src_ip"
        
        # Check RTP Engine detection (should be enabled)
        assert strategy.rtp_engine_detection.enabled is True
        assert strategy.rtp_engine_detection.detection_method == "sdp_change_analysis"
        
        # Check topology
        assert strategy.topology.legs == 4
        
        # Check validation
        assert "carrier" in strategy.validation.required_ips
        assert "core" in strategy.validation.required_ips
        assert "rtp_engine" in strategy.validation.required_ips
    
    def test_get_ip_source(self):
        """Test getting IP source with direction."""
        loader = CorrelationStrategyLoader()
        loader.load_strategies()
        
        strategy = loader.get_strategy("direct_topology")
        assert strategy is not None
        
        # Get carrier IP source (no direction-specific config in direct_topology)
        carrier_source = strategy.get_ip_source("carrier")
        assert carrier_source == "first_invite.src_ip"
        
        # Get core IP source
        core_source = strategy.get_ip_source("core")
        assert core_source == "last_invite.dst_ip"
        
        # Non-existent IP type
        unknown_source = strategy.get_ip_source("unknown")
        assert unknown_source is None
    
    def test_legacy_mapping(self):
        """Test legacy field mapping for backward compatibility."""
        loader = CorrelationStrategyLoader()
        loader.load_strategies()
        
        strategy = loader.get_strategy("direct_topology")
        assert strategy is not None
        
        # Test legacy field access
        carrier_ip_source = strategy.get_legacy_field("carrier_ip_source")
        assert carrier_ip_source == "first_invite.src_ip"
        
        response_priority = strategy.get_legacy_field("response_priority")
        assert response_priority == [183, 200]
    
    def test_get_strategy_function(self):
        """Test convenience function get_strategy()."""
        strategy = get_strategy("direct_topology")
        assert strategy is not None
        assert strategy.name == "direct_topology"
    
    def test_list_strategies(self):
        """Test listing all loaded strategy names."""
        loader = CorrelationStrategyLoader()
        loader.load_strategies()
        
        strategy_names = loader.list_strategies()
        assert isinstance(strategy_names, list)
        assert len(strategy_names) >= 2
        assert "direct_topology" in strategy_names
        assert "rtp_engine_topology" in strategy_names
    
    def test_reload_strategies(self):
        """Test reloading strategies from disk."""
        loader = CorrelationStrategyLoader()
        strategies1 = loader.load_strategies()
        
        # Reload
        strategies2 = loader.reload()
        
        assert len(strategies1) == len(strategies2)
        assert set(strategies1.keys()) == set(strategies2.keys())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
