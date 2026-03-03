"""
Priority-based thread pool executor for RTP capture operations.

Ensures capture operations always have highest priority, preventing blocking
by S3 uploads or correlation jobs.
"""
from __future__ import annotations

import enum
import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

LOGGER = logging.getLogger(__name__)


class PriorityLevel(enum.IntEnum):
    """Priority levels for worker tasks. Lower value = higher priority."""
    CRITICAL = 0  # Live capture operations
    HIGH = 1      # S3 rolling file uploads during capture
    MEDIUM = 2    # S3 final flush after capture
    LOW = 3       # Correlation/post-processing
    
    
@dataclass
class PriorityTask:
    """Task wrapper with priority and execution metadata."""
    priority: PriorityLevel
    fn: Callable
    args: tuple
    kwargs: dict
    name: str
    submitted_at: float
    future: Optional[threading.Event] = None
    result: Any = None
    exception: Optional[Exception] = None


class PriorityThreadPoolExecutor:
    """
    Thread pool executor with priority queue.
    
    Tasks are executed in priority order: CRITICAL > HIGH > MEDIUM > LOW.
    Within same priority level, FIFO order is maintained.
    """
    
    def __init__(self, max_workers: int = 8):
        self._max_workers = max(1, int(max_workers))
        self._task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self._workers: list[threading.Thread] = []
        self._shutdown = False
        self._lock = threading.Lock()
        self._task_counter = 0  # For FIFO within same priority
        
        # Metrics
        self._submitted_count = 0
        self._completed_count = 0
        self._failed_count = 0
        
        self._start_workers()
        LOGGER.info(
            "Priority executor started max_workers=%d",
            self._max_workers,
            extra={"category": "CONFIG"}
        )
    
    def _start_workers(self) -> None:
        """Start worker threads."""
        for i in range(self._max_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"priority-worker-{i}",
                daemon=True
            )
            t.start()
            self._workers.append(t)
    
    def _worker_loop(self) -> None:
        """Main worker loop - picks tasks from priority queue."""
        while not self._shutdown:
            try:
                # Get task with timeout to allow shutdown check
                priority_tuple, task = self._task_queue.get(timeout=1.0)
                
                if task is None:  # Poison pill for shutdown
                    break
                
                self._execute_task(task)
                
            except queue.Empty:
                continue
            except Exception as exc:
                LOGGER.error(
                    "Worker loop error: %s",
                    exc,
                    extra={"category": "ERRORS"},
                    exc_info=True
                )
    
    def _execute_task(self, task: PriorityTask) -> None:
        """Execute a single task and store result."""
        wait_time = time.time() - task.submitted_at
        
        try:
            LOGGER.debug(
                "Executing task name=%s priority=%s wait_time_ms=%.1f",
                task.name,
                task.priority.name,
                wait_time * 1000,
                extra={"category": "PERF"}
            )
            
            result = task.fn(*task.args, **task.kwargs)
            task.result = result
            
            with self._lock:
                self._completed_count += 1
                
        except Exception as exc:
            LOGGER.error(
                "Task execution failed name=%s priority=%s error=%s",
                task.name,
                task.priority.name,
                exc,
                extra={"category": "ERRORS"},
                exc_info=True
            )
            task.exception = exc
            
            with self._lock:
                self._failed_count += 1
        finally:
            if task.future:
                task.future.set()
    
    def submit(
        self,
        fn: Callable,
        *args,
        priority: PriorityLevel = PriorityLevel.MEDIUM,
        name: str = "",
        **kwargs
    ) -> PriorityTask:
        """
        Submit a task with priority.
        
        Args:
            fn: Callable to execute
            *args: Positional arguments
            priority: Task priority level
            name: Task name for logging
            **kwargs: Keyword arguments
            
        Returns:
            PriorityTask with future for result retrieval
        """
        if self._shutdown:
            raise RuntimeError("Executor is shut down")
        
        task_name = name or getattr(fn, '__name__', 'unknown')
        future = threading.Event()
        
        task = PriorityTask(
            priority=priority,
            fn=fn,
            args=args,
            kwargs=kwargs,
            name=task_name,
            submitted_at=time.time(),
            future=future,
        )
        
        with self._lock:
            self._task_counter += 1
            counter = self._task_counter
            self._submitted_count += 1
        
        # Priority tuple: (priority_value, counter) ensures FIFO within same priority
        priority_tuple = (priority.value, counter)
        self._task_queue.put((priority_tuple, task))
        
        LOGGER.debug(
            "Task submitted name=%s priority=%s queue_size=%d",
            task_name,
            priority.name,
            self._task_queue.qsize(),
            extra={"category": "PERF"}
        )
        
        return task
    
    def wait_for_task(self, task: PriorityTask, timeout: Optional[float] = None) -> Any:
        """
        Wait for task completion and return result.
        
        Args:
            task: Task to wait for
            timeout: Maximum wait time in seconds
            
        Returns:
            Task result
            
        Raises:
            Exception: If task raised an exception
            TimeoutError: If timeout exceeded
        """
        if not task.future:
            raise ValueError("Task has no future")
        
        if not task.future.wait(timeout=timeout):
            raise TimeoutError(f"Task {task.name} did not complete within {timeout}s")
        
        if task.exception:
            raise task.exception
        
        return task.result
    
    def get_metrics(self) -> dict[str, int]:
        """Get executor metrics."""
        with self._lock:
            return {
                "submitted": self._submitted_count,
                "completed": self._completed_count,
                "failed": self._failed_count,
                "queue_depth": self._task_queue.qsize(),
                "max_workers": self._max_workers,
            }
    
    def shutdown(self, wait: bool = True, timeout: float = 30.0) -> None:
        """
        Shutdown executor gracefully.
        
        Args:
            wait: Wait for pending tasks to complete
            timeout: Maximum wait time
        """
        LOGGER.info("Shutting down priority executor", extra={"category": "CONFIG"})
        self._shutdown = True
        
        # Send poison pills to all workers
        for _ in range(self._max_workers):
            self._task_queue.put(((999, 0), None))
        
        if wait:
            deadline = time.time() + timeout
            for worker in self._workers:
                remaining = deadline - time.time()
                if remaining > 0:
                    worker.join(timeout=remaining)
        
        LOGGER.info("Priority executor shut down", extra={"category": "CONFIG"})
