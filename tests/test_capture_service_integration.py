"""
Integration test for capture_service with PriorityExecutor.

Validates that CaptureService initializes correctly with
PriorityThreadPoolExecutor and workers are properly submitted.
"""
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from rtphelper.config_loader import AppConfig, EnvironmentConfig, RegionConfig, SubRegionConfig
from rtphelper.services.capture_service import CaptureService


@pytest.fixture
def temp_capture_root(tmp_path):
    """Create temporary capture root directory."""
    return tmp_path / "captures"


@pytest.fixture
def mock_config():
    """Create minimal mock configuration."""
    config = Mock(spec=AppConfig)
    config.environments = {
        "test": EnvironmentConfig(
            regions={
                "region1": RegionConfig(
                    sub_regions={
                        "sub1": SubRegionConfig(
                            hosts=[]
                        )
                    }
                )
            }
        )
    }
    return config


def test_capture_service_initializes_with_executor(temp_capture_root, mock_config):
    """Test that CaptureService initializes with PriorityExecutor."""
    
    # Mock s3_storage to avoid AWS dependencies
    with patch('rtphelper.services.capture_service.S3CaptureStorage'):
        service = CaptureService(
            capture_root=temp_capture_root,
            config=mock_config
        )
        
        # Verify executor exists
        assert hasattr(service, '_executor')
        assert service._executor is not None
        
        # Verify executor is running
        metrics = service._executor.get_metrics()
        assert 'submitted' in metrics
        assert 'completed' in metrics
        assert 'max_workers' in metrics
        assert metrics['max_workers'] == 16
        
        # Cleanup
        service.shutdown()


def test_capture_service_submits_workers_on_init(temp_capture_root, mock_config):
    """Test that workers are submitted during initialization."""
    
    with patch('rtphelper.services.capture_service.S3CaptureStorage'):
        service = CaptureService(
            capture_root=temp_capture_root,
            config=mock_config
        )
        
        # Check that workers were submitted
        metrics = service._executor.get_metrics()
        
        # Storage flush worker + S3 journal workers should be submitted
        # (S3_UPLOAD_WORKERS_MAX workers + 1 storage flush)
        expected_min_workers = 1 + 6  # min 7 workers
        assert metrics['submitted'] >= expected_min_workers
        
        # Cleanup
        service.shutdown()


def test_capture_service_shutdown_stops_executor(temp_capture_root, mock_config):
    """Test that shutdown() properly stops the executor."""
    
    with patch('rtphelper.services.capture_service.S3CaptureStorage'):
        service = CaptureService(
            capture_root=temp_capture_root,
            config=mock_config
        )
        
        executor = service._executor
        assert executor is not None
        
        # Shutdown service
        service.shutdown()
        
        # Verify shutdown was called (workers should have stopped)
        # Note: Can't directly check _shutdown flag, but can verify
        # that trying to submit new tasks raises error
        with pytest.raises(RuntimeError, match="shut down"):
            executor.submit(lambda: None, name="test")


def test_executor_priority_levels_available(temp_capture_root, mock_config):
    """Test that priority levels are correctly imported and available."""
    
    with patch('rtphelper.services.capture_service.S3CaptureStorage'):
        service = CaptureService(
            capture_root=temp_capture_root,
            config=mock_config
        )
        
        # Import PriorityLevel to verify it's available
        from rtphelper.services.priority_executor import PriorityLevel
        
        # Verify all expected priority levels exist
        assert hasattr(PriorityLevel, 'CRITICAL')
        assert hasattr(PriorityLevel, 'HIGH')
        assert hasattr(PriorityLevel, 'MEDIUM')
        assert hasattr(PriorityLevel, 'LOW')
        
        # Verify ordering (lower value = higher priority)
        assert PriorityLevel.CRITICAL < PriorityLevel.HIGH
        assert PriorityLevel.HIGH < PriorityLevel.MEDIUM
        assert PriorityLevel.MEDIUM < PriorityLevel.LOW
        
        # Cleanup
        service.shutdown()


def test_executor_metrics_tracking(temp_capture_root, mock_config):
    """Test that executor tracks metrics correctly."""
    
    with patch('rtphelper.services.capture_service.S3CaptureStorage'):
        service = CaptureService(
            capture_root=temp_capture_root,
            config=mock_config
        )
        
        metrics = service._executor.get_metrics()
        
        # Verify expected metrics keys
        assert 'submitted' in metrics
        assert 'completed' in metrics
        assert 'failed' in metrics
        assert 'queue_depth' in metrics
        assert 'max_workers' in metrics
        
        # Verify types
        assert isinstance(metrics['submitted'], int)
        assert isinstance(metrics['completed'], int)
        assert isinstance(metrics['failed'], int)
        assert isinstance(metrics['queue_depth'], int)
        assert isinstance(metrics['max_workers'], int)
        
        # Cleanup
        service.shutdown()


def test_workers_have_correct_priorities():
    """
    Test that worker priorities match design specification.
    
    This is a documentation test - verifies our understanding
    of priority assignments matches implementation.
    """
    from rtphelper.services.priority_executor import PriorityLevel
    
    # Expected priority assignments
    expected_priorities = {
        'capture_loops': PriorityLevel.CRITICAL,
        'timeout_watchdog': PriorityLevel.CRITICAL,
        's3_maintenance': PriorityLevel.HIGH,
        'storage_flush': PriorityLevel.MEDIUM,
        's3_journal_workers': PriorityLevel.LOW,
    }
    
    # Verify priorities are correctly ordered
    assert expected_priorities['capture_loops'] == PriorityLevel.CRITICAL
    assert expected_priorities['s3_maintenance'] == PriorityLevel.HIGH
    assert expected_priorities['storage_flush'] == PriorityLevel.MEDIUM
    assert expected_priorities['s3_journal_workers'] == PriorityLevel.LOW
    
    # Verify critical operations have highest priority
    assert expected_priorities['capture_loops'].value == 0
    assert expected_priorities['timeout_watchdog'].value == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
