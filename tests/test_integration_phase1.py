"""
Integration tests for Phase 1 refactoring components.

Validates PriorityThreadPoolExecutor and S3UploadCoordinator integration.
"""
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from rtphelper.services.priority_executor import (
    PriorityLevel,
    PriorityThreadPoolExecutor,
)
from rtphelper.services.s3_coordinator import (
    S3UploadCoordinator,
    UploadPhase,
)


def test_priority_executor_with_s3_coordinator_integration():
    """
    Test that S3UploadCoordinator correctly prioritizes uploads via PriorityThreadPoolExecutor.
    
    Scenario:
    1. Submit ROLLING (HIGH), FLUSH (MEDIUM), MAINTENANCE (LOW) uploads
    2. Verify execution order respects priorities
    """
    executor = PriorityThreadPoolExecutor(max_workers=1)
    
    mock_s3 = Mock()
    mock_s3.upload_file.return_value = "s3://bucket/test.pcap"
    
    coordinator = S3UploadCoordinator(mock_s3, executor)
    
    execution_order = []
    
    def track_upload(local_path, relative_file):
        execution_order.append(relative_file)
        time.sleep(0.05)  # Simulate upload delay
        return f"s3://bucket/{relative_file}"
    
    mock_s3.upload_file.side_effect = track_upload
    
    try:
        # Create temp files
        tmp_files = []
        for i in range(3):
            tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            tmp.write(b"test data")
            tmp.close()
            tmp_files.append(Path(tmp.name))
        
        # Submit in reverse priority order
        low_job = coordinator.submit(
            tmp_files[0], "low_priority.pcap", UploadPhase.MAINTENANCE
        )
        medium_job = coordinator.submit(
            tmp_files[1], "medium_priority.pcap", UploadPhase.FLUSH
        )
        high_job = coordinator.submit(
            tmp_files[2], "high_priority.pcap", UploadPhase.ROLLING
        )
        
        # Wait for all uploads
        time.sleep(0.5)
        
        # First upload executes immediately (LOW), then priority order
        assert execution_order[0] == "low_priority.pcap"
        assert execution_order[1] == "high_priority.pcap"  # HIGH priority
        assert execution_order[2] == "medium_priority.pcap"  # MEDIUM priority
        
        # Check metrics
        metrics = coordinator.get_metrics()
        assert metrics["submitted"] == 3
        assert metrics["success"] == 3
        
    finally:
        executor.shutdown(wait=True, timeout=5.0)
        for tmp_path in tmp_files:
            tmp_path.unlink(missing_ok=True)


def test_multiple_rolling_uploads_during_capture():
    """
    Test that multiple ROLLING uploads (during capture) maintain HIGH priority.
    
    Scenario: Simulate capture producing multiple files that need immediate upload.
    """
    executor = PriorityThreadPoolExecutor(max_workers=2)
    
    mock_s3 = Mock()
    mock_s3.upload_file.return_value = "s3://bucket/test.pcap"
    
    coordinator = S3UploadCoordinator(mock_s3, executor)
    
    completed_uploads = []
    
    def track_upload(local_path, relative_file):
        time.sleep(0.1)
        completed_uploads.append(relative_file)
        return f"s3://bucket/{relative_file}"
    
    mock_s3.upload_file.side_effect = track_upload
    
    try:
        # Create 5 temp files
        tmp_files = []
        for i in range(5):
            tmp = tempfile.NamedTemporaryFile(suffix=f"_{i}.pcap", delete=False)
            tmp.write(b"rolling capture data")
            tmp.close()
            tmp_files.append(Path(tmp.name))
        
        # Submit all as ROLLING (HIGH priority)
        jobs = []
        for i, tmp_path in enumerate(tmp_files):
            job = coordinator.submit(
                tmp_path,
                f"rolling_file_{i}.pcap",
                UploadPhase.ROLLING,
                session_id="test-session",
            )
            jobs.append(job)
        
        # Wait for all
        time.sleep(1.0)
        
        # All should complete
        assert len(completed_uploads) == 5
        
        # Check metrics
        metrics = coordinator.get_metrics()
        assert metrics["submitted"] == 5
        assert metrics["success"] == 5
        assert metrics["failure"] == 0
        
    finally:
        executor.shutdown(wait=True, timeout=5.0)
        for tmp_path in tmp_files:
            tmp_path.unlink(missing_ok=True)


def test_executor_priority_with_concurrent_phases():
    """
    Test mixed phases with concurrent execution.
    
    Scenario:
    - Submit MAINTENANCE uploads (LOW priority)
    - While running, submit ROLLING uploads (HIGH priority)
    - HIGH priority should preempt LOW priority
    """
    executor = PriorityThreadPoolExecutor(max_workers=2)
    
    mock_s3 = Mock()
    
    execution_log = []
    
    def track_upload(local_path, relative_file):
        execution_log.append(("start", relative_file, time.time()))
        time.sleep(0.2)  # Simulate slow upload
        execution_log.append(("end", relative_file, time.time()))
        return f"s3://bucket/{relative_file}"
    
    mock_s3.upload_file.side_effect = track_upload
    
    coordinator = S3UploadCoordinator(mock_s3, executor)
    
    try:
        # Create temp files
        tmp_files = [
            tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            for _ in range(4)
        ]
        for tmp in tmp_files:
            tmp.write(b"data")
            tmp.close()
        
        paths = [Path(tmp.name) for tmp in tmp_files]
        
        # Submit 2 MAINTENANCE uploads (LOW priority)
        coordinator.submit(paths[0], "maint1.pcap", UploadPhase.MAINTENANCE)
        coordinator.submit(paths[1], "maint2.pcap", UploadPhase.MAINTENANCE)
        
        # Small delay to let first maintenance upload start
        time.sleep(0.05)
        
        # Submit 2 ROLLING uploads (HIGH priority) - should jump queue
        coordinator.submit(paths[2], "rolling1.pcap", UploadPhase.ROLLING)
        coordinator.submit(paths[3], "rolling2.pcap", UploadPhase.ROLLING)
        
        # Wait for all
        time.sleep(1.5)
        
        # Validate execution order
        start_events = [e for e in execution_log if e[0] == "start"]
        file_order = [e[1] for e in start_events]
        
        # First maintenance starts immediately
        assert file_order[0] == "maint1.pcap"
        
        # Next should be ROLLING (high priority) before second maintenance
        rolling_index = min(
            file_order.index("rolling1.pcap"),
            file_order.index("rolling2.pcap")
        )
        maint2_index = file_order.index("maint2.pcap")
        
        assert rolling_index < maint2_index, "Rolling upload should execute before queued maintenance"
        
    finally:
        executor.shutdown(wait=True, timeout=5.0)
        for path in paths:
            path.unlink(missing_ok=True)


def test_s3_coordinator_batch_submission():
    """Test batch upload submission with mixed priorities."""
    executor = PriorityThreadPoolExecutor(max_workers=4)
    
    mock_s3 = Mock()
    mock_s3.upload_file.return_value = "s3://bucket/file.pcap"
    
    coordinator = S3UploadCoordinator(mock_s3, executor)
    
    try:
        # Create batch of temp files
        tmp_files = []
        files_list = []
        
        for i in range(10):
            tmp = tempfile.NamedTemporaryFile(suffix=f"_{i}.pcap", delete=False)
            tmp.write(f"batch file {i}".encode())
            tmp.close()
            tmp_path = Path(tmp.name)
            tmp_files.append(tmp_path)
            files_list.append((tmp_path, f"batch_file_{i}.pcap"))
        
        # Submit batch
        jobs = coordinator.submit_batch(
            files_list,
            phase=UploadPhase.FLUSH,
            session_id="batch-session",
        )
        
        assert len(jobs) == 10
        
        # Wait for completion
        time.sleep(1.0)
        
        # Check all submitted
        metrics = coordinator.get_metrics()
        assert metrics["submitted"] == 10
        
        # Check summary
        summary = coordinator.format_metrics_summary()
        assert "10" in summary
        assert "successful" in summary
        
    finally:
        executor.shutdown(wait=True, timeout=5.0)
        for tmp_path in tmp_files:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
