#!/usr/bin/env python3
"""
Script to test correlation cancellation and subsequent job processing.

This script simulates:
1. Starting a correlation job
2. Cancelling it while running
3. Starting a new correlation job
4. Verifying the new job completes successfully

Usage:
    python scripts/test_cancellation.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.job_orchestrator import JobOrchestrator, CorrelationJobWorker
import tempfile
import threading


def test_cancellation():
    """Test job cancellation and recovery."""
    print("=" * 70)
    print("CORRELATION CANCELLATION TEST")
    print("=" * 70)
    
    # Create temp database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    print(f"\nTest database: {db_path}")
    
    # Create orchestrator
    orchestrator = JobOrchestrator(db_path)
    
    # Mock handler that simulates long-running work
    handler_started = threading.Event()
    handler_completed = threading.Event()
    
    def mock_handler(payload, progress_callback=None):
        """Simulates a long-running correlation."""
        job_id = payload.get("_job_id", "unknown")
        print(f"\n[Handler] Started job {job_id}")
        handler_started.set()
        
        # Simulate long processing (10 seconds) with cancellation checks
        for i in range(50):
            # Check if cancel was requested via orchestrator
            if orchestrator.is_cancel_requested(job_id):
                print(f"[Handler] Detected cancel request at iteration {i}")
                raise RuntimeError("Correlation canceled by user")
            
            time.sleep(0.2)  # 50 * 0.2 = 10 seconds total
            
            if progress_callback and i % 5 == 0:
                progress_callback({
                    "message": f"Processing iteration {i}/50",
                    "step": "processing",
                    "level": "info"
                })
        
        handler_completed.set()
        print(f"[Handler] Completed job {job_id}")
        return {"status": "success", "job_id": job_id}
    
    # Create worker
    worker = CorrelationJobWorker(orchestrator, mock_handler)
    worker.start()
    
    print("\n1. Testing cancellation of running job...")
    
    # Submit first job
    job1 = orchestrator.submit("correlation", {"test": "job1", "description": "First job to be canceled"})
    job1_id = job1.job_id
    print(f"   Submitted job1: {job1_id}")
    
    # Wait for handler to start
    handler_started.wait(timeout=2.0)
    time.sleep(0.5)  # Let it run a bit
    
    job1 = orchestrator.get(job1_id)
    print(f"   Job1 status before cancel: {job1.status if job1 else 'NOT FOUND'}")
    
    # Cancel the job
    print(f"   Cancelling job1...")
    orchestrator.cancel(job1_id, reason="Test cancellation")
    
    # Wait a bit for cancellation to complete
    time.sleep(2.0)
    
    job1_after = orchestrator.get(job1_id)
    print(f"   Job1 status after cancel: {job1_after.status if job1_after else 'NOT FOUND'}")
    
    if job1_after and job1_after.status == "canceled":
        print("   ✅ Job1 successfully canceled")
    else:
        print(f"   ❌ Job1 not properly canceled (status: {job1_after.status if job1_after else 'NONE'})")
    
    # Reset for next job
    handler_started.clear()
    handler_completed.clear()
    
    print("\n2. Testing new job after cancellation...")
    
    # Submit second job
    job2 = orchestrator.submit("correlation", {"test": "job2", "description": "Second job after cancellation"})
    job2_id = job2.job_id
    print(f"   Submitted job2: {job2_id}")
    
    # Wait for it to be picked up
    time.sleep(1.0)
    
    job2 = orchestrator.get(job2_id)
    print(f"   Job2 status: {job2.status if job2 else 'NOT FOUND'}")
    
    if job2 and job2.status == "running":
        print("   ✅ Job2 started successfully (not stuck in queue)")
    elif job2 and job2.status == "queued":
        print("   ❌ ERROR: Job2 stuck in queue!")
        
        # Debug: check worker state
        print("\n   Debug info:")
        print(f"   - Worker thread alive: {worker._thread.is_alive() if worker._thread else 'NO THREAD'}")
        print(f"   - Worker stop event: {worker._stop_event.is_set()}")
        
        # Try to get next job manually
        print("   - Trying to get next job manually...")
        next_job = orchestrator.next_job_id(timeout=1.0)
        print(f"   - Next job ID: {next_job}")
    else:
        print(f"   ⚠️  Job2 status: {job2.status if job2 else 'NOT FOUND'}")
    
    # Wait a bit more to see if job2 completes
    print("\n   Waiting for job2 to complete (max 15 seconds)...")
    deadline = time.time() + 15
    while time.time() < deadline:
        job2_current = orchestrator.get(job2_id)
        if job2_current and job2_current.status in ["completed", "failed", "canceled"]:
            print(f"   Job2 finished with status: {job2_current.status}")
            break
        time.sleep(0.5)
    else:
        job2_final = orchestrator.get(job2_id)
        print(f"   ❌ Job2 did not complete within timeout (status: {job2_final.status if job2_final else 'NONE'})")
    
    # Stop worker
    print("\n3. Cleaning up...")
    worker.stop(timeout_seconds=3.0)
    
    # Final status check
    print("\n4. Final status check:")
    job1_final = orchestrator.get(job1_id)
    job2_final = orchestrator.get(job2_id)
    
    print(f"   Job1 final status: {job1_final.status if job1_final else 'NOT FOUND'}")
    print(f"   Job2 final status: {job2_final.status if job2_final else 'NOT FOUND'}")
    
    # Results
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    
    success = True
    
    if job1_final and job1_final.status == "canceled":
        print("✅ Job1 was properly canceled")
    else:
        print(f"❌ Job1 status incorrect: {job1_final.status if job1_final else 'NONE'}")
        success = False
    
    if job2_final and job2_final.status == "completed":
        print("✅ Job2 completed successfully after cancellation")
    elif job2_final and job2_final.status == "queued":
        print("❌ Job2 STUCK IN QUEUE - this is the bug!")
        success = False
    else:
        print(f"❌ Job2 did not complete: {job2_final.status if job2_final else 'NONE'}")
        success = False
    
    print("=" * 70)
    
    if success:
        print("✅ ALL TESTS PASSED")
        return 0
    else:
        print("❌ TESTS FAILED")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(test_cancellation())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
