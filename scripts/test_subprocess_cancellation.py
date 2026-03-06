#!/usr/bin/env python3
"""
Test correlation cancellation with subprocess simulation.

This test simulates the real subprocess behavior to identify potential issues.
"""

import sys
import time
import subprocess
import signal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rtphelper.services.job_orchestrator import JobOrchestrator, CorrelationJobWorker
import tempfile
import threading


def test_subprocess_cancellation():
    """Test job cancellation with subprocess that ignores SIGTERM."""
    print("=" * 70)
    print("SUBPROCESS CANCELLATION TEST")
    print("=" * 70)
    
    # Create temp database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    print(f"\nTest database: {db_path}")
    
    # Create orchestrator
    orchestrator = JobOrchestrator(db_path)
    
    # Handler that spawns a subprocess that is slow to terminate
    def subprocess_handler(payload, progress_callback=None):
        """Simulates correlation with subprocess that is slow to terminate."""
        job_id = payload.get("_job_id", "unknown")
        print(f"\n[Handler] Started job {job_id}")
        
        # Spawn a subprocess that sleeps (simulates tshark)
        # This subprocess will ignore SIGTERM for a bit to simulate real behavior
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True
        )
        
        print(f"[Handler] Spawned subprocess PID {proc.pid}")
        
        try:
            # Wait for subprocess with cancellation checks
            deadline = time.time() + 30
            while time.time() < deadline:
                # Check if cancel was requested
                if orchestrator.is_cancel_requested(job_id):
                    print(f"[Handler] Cancel requested, terminating subprocess...")
                    
                    # Try to terminate subprocess
                    try:
                        proc.terminate()
                        print(f"[Handler] Sent SIGTERM to subprocess")
                    except:
                        pass
                    
                    # Wait a bit for graceful shutdown
                    time.sleep(1.0)
                    
                    # Force kill if still running
                    if proc.poll() is None:
                        print(f"[Handler] Subprocess didn't terminate, force killing...")
                        try:
                            proc.kill()
                        except:
                            pass
                    
                    raise RuntimeError("Correlation canceled by user")
                
                # Check if subprocess finished
                if proc.poll() is not None:
                    break
                
                time.sleep(0.2)
            
            # Subprocess completed
            returncode = proc.wait()
            return {"status": "success", "job_id": job_id, "subprocess_returncode": returncode}
            
        finally:
            # Ensure subprocess is killed
            if proc.poll() is None:
                print(f"[Handler] Cleaning up subprocess in finally block...")
                try:
                    proc.kill()
                    proc.wait(timeout=1.0)
                except:
                    pass
    
    # Create worker
    worker = CorrelationJobWorker(orchestrator, subprocess_handler)
    worker.start()
    
    print("\n1. Testing cancellation with subprocess...")
    
    # Submit job
    job1 = orchestrator.submit("correlation", {"test": "job1_subprocess"})
    job1_id = job1.job_id
    print(f"   Submitted job1: {job1_id}")
    
    # Wait for handler to start
    time.sleep(1.0)
    
    job1_check = orchestrator.get(job1_id)
    print(f"   Job1 status before cancel: {job1_check.status if job1_check else 'NOT FOUND'}")
    
    # Cancel the job
    print(f"   Cancelling job1...")
    orchestrator.cancel(job1_id, reason="Test subprocess cancellation")
    
    # Wait for cancellation to complete (may take longer with subprocess)
    print(f"   Waiting for cancellation to complete...")
    time.sleep(3.0)
    
    job1_after = orchestrator.get(job1_id)
    print(f"   Job1 status after cancel: {job1_after.status if job1_after else 'NOT FOUND'}")
    
    if job1_after and job1_after.status == "canceled":
        print("   ✅ Job1 successfully canceled")
    else:
        print(f"   ❌ Job1 not properly canceled (status: {job1_after.status if job1_after else 'NONE'})")
    
    print("\n2. Testing new job after subprocess cancellation...")
    
    # Submit second job (fast one without subprocess)
    job2 = orchestrator.submit("correlation", {"test": "job2_fast"})
    job2_id = job2.job_id
    print(f"   Submitted job2: {job2_id}")
    
    # Wait for it to be picked up
    time.sleep(1.0)
    
    job2_check = orchestrator.get(job2_id)
    print(f"   Job2 status after 1s: {job2_check.status if job2_check else 'NOT FOUND'}")
    
    if job2_check and job2_check.status == "queued":
        print("   ⚠️  Job2 still queued after 1 second")
        
        # Debug info
        print("\n   Debug info:")
        print(f"   - Worker thread alive: {worker._thread.is_alive() if worker._thread else 'NO THREAD'}")
        print(f"   - Worker stop event: {worker._stop_event.is_set()}")
        
        # Wait more
        print("   - Waiting 5 more seconds...")
        time.sleep(5.0)
        
        job2_check2 = orchestrator.get(job2_id)
        print(f"   - Job2 status after 6s total: {job2_check2.status if job2_check2 else 'NOT FOUND'}")
        
        if job2_check2 and job2_check2.status == "queued":
            print("   ❌ ERROR: Job2 STUCK IN QUEUE after 6 seconds!")
        else:
            print(f"   ⚠️  Job2 eventually started: {job2_check2.status if job2_check2 else 'NONE'}")
    else:
        print(f"   ✅ Job2 started/completed: {job2_check.status if job2_check else 'NONE'}")
    
    # Stop worker
    print("\n3. Cleaning up...")
    worker.stop(timeout_seconds=5.0)
    
    # Final status
    print("\n4. Final status:")
    job1_final = orchestrator.get(job1_id)
    job2_final = orchestrator.get(job2_id)
    
    print(f"   Job1: {job1_final.status if job1_final else 'NOT FOUND'}")
    print(f"   Job2: {job2_final.status if job2_final else 'NOT FOUND'}")
    
    # Results
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    
    success = True
    
    if job1_final and job1_final.status == "canceled":
        print("✅ Job1 (with subprocess) was properly canceled")
    else:
        print(f"❌ Job1 status incorrect: {job1_final.status if job1_final else 'NONE'}")
        success = False
    
    if job2_final and job2_final.status in ["completed", "running"]:
        print("✅ Job2 started/completed after subprocess cancellation")
    elif job2_final and job2_final.status == "queued":
        print("❌ Job2 STUCK IN QUEUE - subprocess didn't cleanup properly!")
        success = False
    else:
        print(f"⚠️  Job2 unexpected status: {job2_final.status if job2_final else 'NONE'}")
        success = False
    
    print("=" * 70)
    
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(test_subprocess_cancellation())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
