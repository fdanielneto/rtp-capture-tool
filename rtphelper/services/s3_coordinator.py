"""
Unified S3 upload coordinator with priority-based scheduling.

Replaces 3 separate upload mechanisms:
1. Rolling uploads (during capture) - HIGH priority
2. Final flush (after capture) - MEDIUM priority
3. Maintenance cleanup - LOW priority
"""
from __future__ import annotations

import enum
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from rtphelper.services.priority_executor import (
    PriorityLevel,
    PriorityThreadPoolExecutor,
)
from rtphelper.services.s3_storage import S3CaptureStorage

LOGGER = logging.getLogger(__name__)


class UploadPhase(enum.Enum):
    """Upload phase determines priority level."""
    ROLLING = "rolling"    # During capture - HIGH priority
    FLUSH = "flush"        # After capture - MEDIUM priority
    MAINTENANCE = "maintenance"  # Cleanup/housekeeping - LOW priority


@dataclass
class UploadResult:
    """Result of a single upload operation."""
    local_path: Path
    relative_file: str
    s3_key: Optional[str] = None
    success: bool = False
    error: Optional[str] = None
    attempt_count: int = 0
    duration_ms: float = 0.0


@dataclass
class UploadJob:
    """Upload job with metadata and tracking."""
    local_path: Path
    relative_file: str
    phase: UploadPhase
    session_id: str = ""
    submitted_at: float = field(default_factory=time.time)
    result: Optional[UploadResult] = None
    task: Optional[Any] = None  # PriorityTask reference


class S3UploadCoordinator:
    """
    Coordinate S3 uploads with priority scheduling.
    
    Uses PriorityThreadPoolExecutor to ensure rolling uploads during capture
    have higher priority than final flush or maintenance operations.
    """
    
    def __init__(
        self,
        s3_storage: S3CaptureStorage,
        executor: PriorityThreadPoolExecutor,
    ):
        self._s3 = s3_storage
        self._executor = executor
        self._lock = threading.Lock()
        
        # Tracking
        self._submitted_count = 0
        self._success_count = 0
        self._failure_count = 0
        self._total_bytes_uploaded = 0
        
        # Phase => priority mapping
        self._phase_priority = {
            UploadPhase.ROLLING: PriorityLevel.HIGH,
            UploadPhase.FLUSH: PriorityLevel.MEDIUM,
            UploadPhase.MAINTENANCE: PriorityLevel.LOW,
        }
        
        LOGGER.info("S3UploadCoordinator initialized", extra={"category": "CONFIG"})
    
    def _upload_priority(self, phase: UploadPhase) -> PriorityLevel:
        """Map upload phase to priority level."""
        return self._phase_priority.get(phase, PriorityLevel.MEDIUM)
    
    def submit(
        self,
        local_path: Path,
        relative_file: str,
        phase: UploadPhase = UploadPhase.FLUSH,
        session_id: str = "",
    ) -> UploadJob:
        """
        Submit file for S3 upload.
        
        Args:
            local_path: Local file path
            relative_file: Relative path for S3 key construction
            phase: Upload phase (determines priority)
            session_id: Session identifier for tracking
            
        Returns:
            UploadJob that can be awaited for result
        """
        job = UploadJob(
            local_path=local_path,
            relative_file=relative_file,
            phase=phase,
            session_id=session_id,
        )
        
        priority = self._upload_priority(phase)
        
        # Submit to executor
        task = self._executor.submit(
            self._execute_upload,
            job,
            priority=priority,
            name=f"s3_upload_{phase.value}_{local_path.name}",
        )
        
        # Store task reference for waiting
        job.task = task
        
        # Track submission
        with self._lock:
            self._submitted_count += 1
        
        # Store task reference for result retrieval
        job.result = UploadResult(
            local_path=local_path,
            relative_file=relative_file,
        )
        
        LOGGER.debug(
            "Upload submitted file=%s phase=%s priority=%s session=%s",
            local_path.name,
            phase.value,
            priority.name,
            session_id or "none",
            extra={"category": "FILES"},
        )
        
        return job
    
    def _execute_upload(self, job: UploadJob) -> UploadResult:
        """Execute S3 upload with retries and metrics."""
        start_time = time.time()
        result = job.result or UploadResult(
            local_path=job.local_path,
            relative_file=job.relative_file,
        )
        
        try:
            # Check file exists and get size
            if not job.local_path.exists():
                raise FileNotFoundError(f"Local file not found: {job.local_path}")
            
            file_size = job.local_path.stat().st_size
            
            # Execute upload (s3_storage.py handles retries internally)
            s3_key = self._s3.upload_file(job.local_path, job.relative_file)
            
            # Update result
            result.s3_key = s3_key
            result.success = True
            result.duration_ms = (time.time() - start_time) * 1000
            
            # Update metrics
            with self._lock:
                self._success_count += 1
                self._total_bytes_uploaded += file_size
            
            LOGGER.info(
                "Upload completed file=%s s3_key=%s size_bytes=%d duration_ms=%.1f phase=%s",
                job.local_path.name,
                s3_key,
                file_size,
                result.duration_ms,
                job.phase.value,
                extra={"category": "FILES"},
            )
            
        except Exception as exc:
            result.success = False
            result.error = str(exc)
            result.duration_ms = (time.time() - start_time) * 1000
            
            with self._lock:
                self._failure_count += 1
            
            LOGGER.error(
                "Upload failed file=%s phase=%s duration_ms=%.1f error=%s",
                job.local_path.name,
                job.phase.value,
                result.duration_ms,
                exc,
                extra={"category": "ERRORS"},
                exc_info=True,
            )
        
        return result
    
    def submit_batch(
        self,
        files: list[tuple[Path, str]],
        phase: UploadPhase = UploadPhase.FLUSH,
        session_id: str = "",
    ) -> list[UploadJob]:
        """
        Submit batch of files for upload.
        
        Args:
            files: List of (local_path, relative_file) tuples
            phase: Upload phase for all files
            session_id: Session identifier
            
        Returns:
            List of UploadJob instances
        """
        jobs = []
        for local_path, relative_file in files:
            job = self.submit(local_path, relative_file, phase, session_id)
            jobs.append(job)
        
        LOGGER.info(
            "Batch submitted count=%d phase=%s session=%s",
            len(jobs),
            phase.value,
            session_id or "none",
            extra={"category": "FILES"},
        )
        
        return jobs
    
    def wait_for_job(self, job: UploadJob, timeout: Optional[float] = None) -> UploadResult:
        """
        Wait for upload job to complete.
        
        Args:
            job: UploadJob to wait for
            timeout: Maximum wait time in seconds
            
        Returns:
            UploadResult with success/error information
            
        Raises:
            TimeoutError: If timeout exceeded
            RuntimeError: If job has no task reference
        """
        if not job.task:
            raise RuntimeError("Job has no task reference")
        
        # Wait for task to complete and get result
        result = self._executor.wait_for_task(job.task, timeout=timeout)
        
        # Update job result
        job.result = result
        
        return result
    
    def get_metrics(self) -> dict[str, int | float]:
        """Get upload coordinator metrics."""
        with self._lock:
            return {
                "submitted": self._submitted_count,
                "success": self._success_count,
                "failure": self._failure_count,
                "total_bytes": self._total_bytes_uploaded,
                "success_rate": (
                    self._success_count / self._submitted_count * 100
                    if self._submitted_count > 0
                    else 0.0
                ),
            }
    
    def format_metrics_summary(self) -> str:
        """Format metrics as human-readable string."""
        metrics = self.get_metrics()
        total_mb = metrics["total_bytes"] / (1024 * 1024)
        
        return (
            f"S3 Uploads: {metrics['success']}/{metrics['submitted']} successful "
            f"({metrics['success_rate']:.1f}%), "
            f"{total_mb:.1f} MB uploaded, "
            f"{metrics['failure']} failures"
        )
