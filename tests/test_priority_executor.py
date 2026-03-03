"""
Unit tests for PriorityThreadPoolExecutor.

Validates priority ordering, FIFO within same priority, metrics, and shutdown.
"""
import time
import pytest

from rtphelper.services.priority_executor import (
    PriorityThreadPoolExecutor,
    PriorityLevel,
)


def test_priority_executor_basic_execution():
    """Test basic task submission and execution."""
    executor = PriorityThreadPoolExecutor(max_workers=2)
    
    def add_numbers(a, b):
        return a + b
    
    task = executor.submit(add_numbers, 3, 5, name="add_test")
    result = executor.wait_for_task(task, timeout=5.0)
    
    assert result == 8
    executor.shutdown()


def test_priority_ordering():
    """Test that CRITICAL tasks execute before LOW tasks."""
    executor = PriorityThreadPoolExecutor(max_workers=1)
    
    execution_order = []
    lock = executor._lock  # Reuse executor's lock
    
    def task_fn(name):
        time.sleep(0.05)  # Ensure tasks queue up
        with lock:
            execution_order.append(name)
    
    # Submit in reverse priority order
    low_task = executor.submit(
        task_fn, "LOW", priority=PriorityLevel.LOW, name="low_task"
    )
    medium_task = executor.submit(
        task_fn, "MEDIUM", priority=PriorityLevel.MEDIUM, name="medium_task"
    )
    high_task = executor.submit(
        task_fn, "HIGH", priority=PriorityLevel.HIGH, name="high_task"
    )
    critical_task = executor.submit(
        task_fn, "CRITICAL", priority=PriorityLevel.CRITICAL, name="critical_task"
    )
    
    # Wait for all tasks
    executor.wait_for_task(low_task, timeout=5.0)
    executor.wait_for_task(medium_task, timeout=5.0)
    executor.wait_for_task(high_task, timeout=5.0)
    executor.wait_for_task(critical_task, timeout=5.0)
    
    executor.shutdown()
    
    # First task executes immediately (LOW), rest follow priority order
    assert execution_order[0] == "LOW"
    assert execution_order[1] == "CRITICAL"
    assert execution_order[2] == "HIGH"
    assert execution_order[3] == "MEDIUM"


def test_fifo_within_same_priority():
    """Test FIFO ordering within same priority level."""
    executor = PriorityThreadPoolExecutor(max_workers=1)
    
    execution_order = []
    lock = executor._lock
    
    def task_fn(task_id):
        time.sleep(0.01)
        with lock:
            execution_order.append(task_id)
    
    # Submit 5 tasks with same priority
    tasks = []
    for i in range(5):
        task = executor.submit(
            task_fn, i, priority=PriorityLevel.MEDIUM, name=f"task_{i}"
        )
        tasks.append(task)
    
    # Wait for all
    for task in tasks:
        executor.wait_for_task(task, timeout=5.0)
    
    executor.shutdown()
    
    # Should execute in FIFO order
    assert execution_order == [0, 1, 2, 3, 4]


def test_task_exception_handling():
    """Test that task exceptions are captured and can be raised."""
    executor = PriorityThreadPoolExecutor(max_workers=2)
    
    def failing_task():
        raise ValueError("Test error")
    
    task = executor.submit(failing_task, name="failing_task")
    
    with pytest.raises(ValueError, match="Test error"):
        executor.wait_for_task(task, timeout=5.0)
    
    # Metrics should count failure
    metrics = executor.get_metrics()
    assert metrics["failed"] == 1
    assert metrics["completed"] == 0
    
    executor.shutdown()


def test_timeout():
    """Test timeout on wait_for_task."""
    executor = PriorityThreadPoolExecutor(max_workers=1)
    
    def slow_task():
        time.sleep(5.0)
    
    task = executor.submit(slow_task, name="slow_task")
    
    with pytest.raises(TimeoutError):
        executor.wait_for_task(task, timeout=0.1)
    
    executor.shutdown(wait=False)


def test_metrics():
    """Test executor metrics tracking."""
    executor = PriorityThreadPoolExecutor(max_workers=2)
    
    def success_task():
        return "OK"
    
    def fail_task():
        raise RuntimeError("Failure")
    
    # Submit mix of tasks
    t1 = executor.submit(success_task, name="success_1")
    t2 = executor.submit(success_task, name="success_2")
    t3 = executor.submit(fail_task, name="fail_1")
    
    executor.wait_for_task(t1, timeout=5.0)
    executor.wait_for_task(t2, timeout=5.0)
    
    try:
        executor.wait_for_task(t3, timeout=5.0)
    except RuntimeError:
        pass
    
    metrics = executor.get_metrics()
    assert metrics["submitted"] == 3
    assert metrics["completed"] == 2
    assert metrics["failed"] == 1
    assert metrics["max_workers"] == 2
    
    executor.shutdown()


def test_multiple_workers_parallel_execution():
    """Test that multiple workers execute tasks in parallel."""
    executor = PriorityThreadPoolExecutor(max_workers=4)
    
    start_times = {}
    lock = executor._lock
    
    def parallel_task(task_id):
        with lock:
            start_times[task_id] = time.time()
        time.sleep(0.1)
    
    # Submit 4 tasks simultaneously
    tasks = [
        executor.submit(parallel_task, i, name=f"parallel_{i}")
        for i in range(4)
    ]
    
    # Wait for all
    for task in tasks:
        executor.wait_for_task(task, timeout=5.0)
    
    executor.shutdown()
    
    # All 4 should start within small window (parallel execution)
    times = sorted(start_times.values())
    time_spread = times[-1] - times[0]
    assert time_spread < 0.05  # All started within 50ms


def test_shutdown_with_pending_tasks():
    """Test graceful shutdown with pending tasks."""
    executor = PriorityThreadPoolExecutor(max_workers=1)
    
    completed = []
    lock = executor._lock
    
    def task_fn(task_id):
        time.sleep(0.05)
        with lock:
            completed.append(task_id)
    
    # Submit 5 tasks (only 1 worker, so 4 will be pending)
    tasks = [
        executor.submit(task_fn, i, name=f"task_{i}")
        for i in range(5)
    ]
    
    # Immediate shutdown with wait
    executor.shutdown(wait=True, timeout=5.0)
    
    # All tasks should complete
    assert len(completed) == 5


def test_cannot_submit_after_shutdown():
    """Test that submission after shutdown raises error."""
    executor = PriorityThreadPoolExecutor(max_workers=2)
    executor.shutdown(wait=False)
    
    with pytest.raises(RuntimeError, match="shut down"):
        executor.submit(lambda: None, name="late_task")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
