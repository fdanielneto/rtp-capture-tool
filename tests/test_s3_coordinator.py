"""
Unit tests for S3UploadCoordinator.

Validates priority-based upload scheduling, batch operations, and metrics.
"""
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from rtphelper.services.s3_coordinator import (
    S3UploadCoordinator,
    UploadPhase,
    UploadJob,
)
from rtphelper.services.priority_executor import PriorityThreadPoolExecutor


@pytest.fixture
def mock_s3_storage():
    """Create mock S3CaptureStorage."""
    mock = Mock()
    mock.upload_file.return_value = "test-bucket/test-key.pcap"
    return mock


@pytest.fixture
def executor():
    """Create real executor for integration testing."""
    exec = PriorityThreadPoolExecutor(max_workers=2)
    yield exec
    exec.shutdown(wait=True, timeout=5.0)


@pytest.fixture
def coordinator(mock_s3_storage, executor):
    """Create S3UploadCoordinator with mocks."""
    return S3UploadCoordinator(mock_s3_storage, executor)


def test_coordinator_initialization(mock_s3_storage, executor):
    """Test coordinator initializes correctly."""
    coord = S3UploadCoordinator(mock_s3_storage, executor)
    
    metrics = coord.get_metrics()
    assert metrics["submitted"] == 0
    assert metrics["success"] == 0
    assert metrics["failure"] == 0


def test_submit_upload_rolling_phase(coordinator, mock_s3_storage):
    """Test submitting upload with ROLLING phase (HIGH priority)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"test data")
        tmp_path = Path(tmp.name)
    
    try:
        job = coordinator.submit(
            local_path=tmp_path,
            relative_file="test/file.pcap",
            phase=UploadPhase.ROLLING,
            session_id="test-session",
        )
        
        assert job.local_path == tmp_path
        assert job.phase == UploadPhase.ROLLING
        assert job.session_id == "test-session"
        
        metrics = coordinator.get_metrics()
        assert metrics["submitted"] == 1
        
    finally:
        tmp_path.unlink(missing_ok=True)


def test_submit_upload_flush_phase(coordinator, mock_s3_storage):
    """Test submitting upload with FLUSH phase (MEDIUM priority)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"test data")
        tmp_path = Path(tmp.name)
    
    try:
        job = coordinator.submit(
            local_path=tmp_path,
            relative_file="test/file.pcap",
            phase=UploadPhase.FLUSH,
        )
        
        assert job.phase == UploadPhase.FLUSH
        
    finally:
        tmp_path.unlink(missing_ok=True)


def test_submit_upload_maintenance_phase(coordinator, mock_s3_storage):
    """Test submitting upload with MAINTENANCE phase (LOW priority)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"test data")
        tmp_path = Path(tmp.name)
    
    try:
        job = coordinator.submit(
            local_path=tmp_path,
            relative_file="test/file.pcap",
            phase=UploadPhase.MAINTENANCE,
        )
        
        assert job.phase == UploadPhase.MAINTENANCE
        
    finally:
        tmp_path.unlink(missing_ok=True)


def test_submit_batch(coordinator, mock_s3_storage):
    """Test batch upload submission."""
    files = []
    tmp_paths = []
    
    try:
        # Create 3 temp files
        for i in range(3):
            tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            tmp.write(f"file {i} data".encode())
            tmp.close()
            tmp_path = Path(tmp.name)
            tmp_paths.append(tmp_path)
            files.append((tmp_path, f"batch/file_{i}.pcap"))
        
        jobs = coordinator.submit_batch(
            files=files,
            phase=UploadPhase.FLUSH,
            session_id="batch-session",
        )
        
        assert len(jobs) == 3
        for job in jobs:
            assert job.phase == UploadPhase.FLUSH
            assert job.session_id == "batch-session"
        
        metrics = coordinator.get_metrics()
        assert metrics["submitted"] == 3
        
    finally:
        for tmp_path in tmp_paths:
            tmp_path.unlink(missing_ok=True)


def test_upload_execution_success(coordinator, mock_s3_storage):
    """Test successful upload execution and metrics."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"test data" * 100)
        tmp_path = Path(tmp.name)
    
    try:
        job = coordinator.submit(
            local_path=tmp_path,
            relative_file="test/success.pcap",
            phase=UploadPhase.FLUSH,
        )
        
        # Give time for execution
        import time
        time.sleep(0.5)
        
        # Check metrics updated
        metrics = coordinator.get_metrics()
        assert metrics["submitted"] >= 1
        
        # Verify S3 upload was called
        assert mock_s3_storage.upload_file.called
        
    finally:
        tmp_path.unlink(missing_ok=True)


def test_upload_execution_file_not_found(coordinator, mock_s3_storage):
    """Test upload failure when file doesn't exist."""
    nonexistent_path = Path("/tmp/nonexistent_file_12345.pcap")
    
    job = coordinator.submit(
        local_path=nonexistent_path,
        relative_file="test/missing.pcap",
        phase=UploadPhase.FLUSH,
    )
    
    # Give time for execution
    import time
    time.sleep(0.5)
    
    # Check failure counted
    metrics = coordinator.get_metrics()
    assert metrics["failure"] >= 1


def test_upload_execution_s3_error(coordinator, mock_s3_storage):
    """Test upload failure when S3 raises error."""
    mock_s3_storage.upload_file.side_effect = RuntimeError("S3 connection error")
    
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"test data")
        tmp_path = Path(tmp.name)
    
    try:
        job = coordinator.submit(
            local_path=tmp_path,
            relative_file="test/error.pcap",
            phase=UploadPhase.FLUSH,
        )
        
        # Give time for execution
        import time
        time.sleep(0.5)
        
        # Check failure counted
        metrics = coordinator.get_metrics()
        assert metrics["failure"] >= 1
        
    finally:
        tmp_path.unlink(missing_ok=True)


def test_metrics_success_rate():
    """Test success rate calculation in metrics."""
    mock_s3 = Mock()
    executor = PriorityThreadPoolExecutor(max_workers=2)
    coord = S3UploadCoordinator(mock_s3, executor)
    
    try:
        # Simulate metrics manually (bypassing actual upload)
        coord._submitted_count = 10
        coord._success_count = 8
        coord._failure_count = 2
        
        metrics = coord.get_metrics()
        assert metrics["success_rate"] == 80.0
        
    finally:
        executor.shutdown(wait=False)


def test_metrics_zero_division():
    """Test metrics don't crash with zero submissions."""
    mock_s3 = Mock()
    executor = PriorityThreadPoolExecutor(max_workers=2)
    coord = S3UploadCoordinator(mock_s3, executor)
    
    try:
        metrics = coord.get_metrics()
        assert metrics["success_rate"] == 0.0
        
    finally:
        executor.shutdown(wait=False)


def test_format_metrics_summary():
    """Test metrics summary formatting."""
    mock_s3 = Mock()
    executor = PriorityThreadPoolExecutor(max_workers=2)
    coord = S3UploadCoordinator(mock_s3, executor)
    
    try:
        # Simulate metrics
        coord._submitted_count = 100
        coord._success_count = 95
        coord._failure_count = 5
        coord._total_bytes_uploaded = 1024 * 1024 * 50  # 50 MB
        
        summary = coord.format_metrics_summary()
        
        assert "95/100" in summary
        assert "95.0%" in summary
        assert "50.0 MB" in summary
        assert "5 failures" in summary
        
    finally:
        executor.shutdown(wait=False)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
