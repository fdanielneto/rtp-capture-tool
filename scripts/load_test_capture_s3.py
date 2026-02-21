#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import queue
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rtphelper.rpcap.pcap_writer import RollingPcapWriter


class RateLimiter:
    def __init__(self, rate_bytes_per_sec: float) -> None:
        self.rate_bps = max(0.0, float(rate_bytes_per_sec))
        self._start = time.perf_counter()
        self._scheduled_bytes = 0.0

    def wait_for(self, byte_count: int) -> None:
        if self.rate_bps <= 0:
            return
        self._scheduled_bytes += float(max(0, byte_count))
        target_elapsed = self._scheduled_bytes / self.rate_bps
        elapsed = time.perf_counter() - self._start
        if target_elapsed > elapsed:
            time.sleep(target_elapsed - elapsed)


@dataclass
class StageResult:
    stage: int
    upload_limit_mbps: float
    target_pps: int
    duration_s: int
    produced_packets: int
    dropped_packets: int
    written_packets: int
    written_bytes: int
    uploaded_bytes: int
    upload_files: int
    write_errors: int
    upload_errors: int
    avg_write_latency_ms: float
    p95_write_latency_ms: float
    avg_cpu_pct: float
    avg_mem_mb: float
    pending_upload_mb_end: float
    degraded: bool
    degraded_reasons: List[str] = field(default_factory=list)

    @property
    def drop_rate(self) -> float:
        if self.produced_packets <= 0:
            return 0.0
        return self.dropped_packets / self.produced_packets

    @property
    def capture_pps(self) -> float:
        if self.duration_s <= 0:
            return 0.0
        return self.produced_packets / self.duration_s

    @property
    def disk_mbps(self) -> float:
        if self.duration_s <= 0:
            return 0.0
        return (self.written_bytes / (1024 * 1024)) / self.duration_s

    @property
    def upload_mbps(self) -> float:
        if self.duration_s <= 0:
            return 0.0
        return (self.uploaded_bytes / (1024 * 1024)) / self.duration_s


@dataclass
class ModeSummary:
    upload_limit_mbps: float
    max_sustainable_pps: int
    degraded_at_pps: Optional[int]


class RuntimeCounters:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.produced_packets = 0
        self.dropped_packets = 0
        self.written_packets = 0
        self.written_bytes = 0
        self.uploaded_bytes = 0
        self.upload_files = 0
        self.write_errors = 0
        self.upload_errors = 0
        self.pending_upload_bytes = 0
        self.write_latencies_ms: List[float] = []
        self.cpu_samples: List[float] = []
        self.mem_samples_mb: List[float] = []


def _parse_upload_modes(raw: str) -> List[float]:
    vals: List[float] = []
    for token in str(raw or "").split(","):
        t = token.strip().lower()
        if not t:
            continue
        if t in {"0", "unlimited", "inf", "infinite"}:
            vals.append(0.0)
            continue
        vals.append(max(0.0, float(t)))
    if not vals:
        return [3.0, 1.0, 5.0, 0.0]
    # keep order but remove duplicates
    dedup: List[float] = []
    seen = set()
    for v in vals:
        key = round(v, 6)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(v)
    return dedup


def _get_process_sampler():
    try:
        import psutil  # type: ignore

        p = psutil.Process(os.getpid())
        p.cpu_percent(interval=None)

        def sample() -> tuple[float, float]:
            cpu = float(p.cpu_percent(interval=None))
            mem = float(p.memory_info().rss / (1024 * 1024))
            return cpu, mem

        return sample
    except Exception:
        try:
            import resource
        except Exception:
            resource = None  # type: ignore

        last_t = time.perf_counter()
        last_cpu = time.process_time()

        def sample() -> tuple[float, float]:
            nonlocal last_t, last_cpu
            now_t = time.perf_counter()
            now_cpu = time.process_time()
            dt_wall = max(1e-9, now_t - last_t)
            cpu_pct = max(0.0, min(100.0, ((now_cpu - last_cpu) / dt_wall) * 100.0))
            last_t = now_t
            last_cpu = now_cpu
            mem_mb = 0.0
            if resource is not None:
                try:
                    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                    # macOS reports bytes, Linux reports KB.
                    mem_mb = float(rss / (1024 * 1024)) if sys.platform == "darwin" else float(rss / 1024)
                except Exception:
                    mem_mb = 0.0
            return cpu_pct, mem_mb

        return sample


def _payload(size: int) -> bytes:
    return (b"RTPLOAD" * ((size // 7) + 1))[:size]


def run_stage(
    *,
    stage: int,
    out_dir: Path,
    target_pps: int,
    duration_s: int,
    packet_size: int,
    queue_size: int,
    segment_size_mb: int,
    upload_limit_mbps: float,
    local_write_limit_mbps: float,
    drop_threshold: float,
    latency_threshold_ms: float,
    pending_upload_threshold_mb: float,
) -> StageResult:
    stage_dir = out_dir / f"stage_{stage:03d}_u{str(upload_limit_mbps).replace('.', '_')}_pps{target_pps}"
    raw_dir = stage_dir / "raw"
    uploaded_dir = stage_dir / "uploaded_simulated"
    raw_dir.mkdir(parents=True, exist_ok=True)
    uploaded_dir.mkdir(parents=True, exist_ok=True)

    writer = RollingPcapWriter(
        base_dir=raw_dir,
        file_prefix="rtp-bench",
        max_bytes=max(1, segment_size_mb) * 1024 * 1024,
        linktype=1,
        snaplen=262144,
    )

    capture_q: "queue.Queue[tuple[float, int, int, bytes, int]]" = queue.Queue(maxsize=max(1000, queue_size))
    upload_q: "queue.Queue[Path]" = queue.Queue()
    counters = RuntimeCounters()

    stop_event = threading.Event()
    producer_done = threading.Event()
    writer_done = threading.Event()

    write_limiter = RateLimiter(local_write_limit_mbps * 1024 * 1024) if local_write_limit_mbps > 0 else None
    upload_limiter = RateLimiter(upload_limit_mbps * 1024 * 1024) if upload_limit_mbps > 0 else None
    proc_sample = _get_process_sampler()
    payload = _payload(max(64, packet_size))

    def producer() -> None:
        start = time.perf_counter()
        next_tick = start
        interval = 1.0 / float(max(1, target_pps))
        while True:
            now = time.perf_counter()
            if now - start >= duration_s:
                break
            if now < next_tick:
                time.sleep(next_tick - now)
                continue
            wall = time.time()
            ts_sec = int(wall)
            ts_usec = int((wall - ts_sec) * 1_000_000)
            enqueue_at = time.perf_counter()
            with counters.lock:
                counters.produced_packets += 1
            try:
                capture_q.put_nowait((enqueue_at, ts_sec, ts_usec, payload, len(payload)))
            except queue.Full:
                with counters.lock:
                    counters.dropped_packets += 1
            next_tick += interval
        producer_done.set()

    def writer_consumer() -> None:
        prev_file: Optional[Path] = None
        while True:
            if producer_done.is_set() and capture_q.empty():
                break
            try:
                enqueue_at, ts_sec, ts_usec, data, orig_len = capture_q.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if write_limiter is not None:
                    write_limiter.wait_for(len(data) + 16)
                before = writer._current_path  # noqa: SLF001
                writer.write_packet(ts_sec, ts_usec, data, orig_len)
                after = writer._current_path  # noqa: SLF001
                now = time.perf_counter()
                latency_ms = (now - enqueue_at) * 1000.0
                rec_bytes = len(data) + 16
                with counters.lock:
                    counters.written_packets += 1
                    counters.written_bytes += rec_bytes
                    counters.write_latencies_ms.append(latency_ms)
                if before is not None and after is not None and before != after:
                    file_size = int(before.stat().st_size) if before.exists() else 0
                    upload_q.put(before)
                    with counters.lock:
                        counters.pending_upload_bytes += file_size
                prev_file = after
            except Exception:
                with counters.lock:
                    counters.write_errors += 1
            finally:
                capture_q.task_done()
        writer.close()
        if prev_file is not None and prev_file.exists():
            file_size = int(prev_file.stat().st_size)
            upload_q.put(prev_file)
            with counters.lock:
                counters.pending_upload_bytes += file_size
        writer_done.set()

    def uploader() -> None:
        while True:
            # Benchmark focus: upload during active capture/write concurrency window.
            # Do not drain backlog after writer is done; backlog is a degradation signal.
            if writer_done.is_set():
                break
            try:
                file_path = upload_q.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                size = int(file_path.stat().st_size)
                if upload_limiter is not None:
                    upload_limiter.wait_for(size)
                # Simulated S3 sink (intentionally local-only; no external S3 access).
                sink = uploaded_dir / file_path.name
                if not sink.exists():
                    sink.write_bytes(file_path.read_bytes())
                with counters.lock:
                    counters.uploaded_bytes += size
                    counters.upload_files += 1
                    counters.pending_upload_bytes = max(0, counters.pending_upload_bytes - size)
            except Exception:
                with counters.lock:
                    counters.upload_errors += 1
            finally:
                upload_q.task_done()

    def monitor() -> None:
        while not stop_event.is_set():
            cpu, mem = proc_sample()
            with counters.lock:
                counters.cpu_samples.append(cpu)
                counters.mem_samples_mb.append(mem)
            time.sleep(1.0)

    t_prod = threading.Thread(target=producer, name=f"lt-prod-{stage}", daemon=True)
    t_wri = threading.Thread(target=writer_consumer, name=f"lt-wri-{stage}", daemon=True)
    t_upl = threading.Thread(target=uploader, name=f"lt-upl-{stage}", daemon=True)
    t_mon = threading.Thread(target=monitor, name=f"lt-mon-{stage}", daemon=True)

    t_prod.start()
    t_wri.start()
    t_upl.start()
    t_mon.start()
    t_prod.join()
    t_wri.join()
    t_upl.join()
    stop_event.set()
    t_mon.join(timeout=2.0)

    with counters.lock:
        lat = list(counters.write_latencies_ms)
        avg_lat = float(statistics.fmean(lat)) if lat else 0.0
        p95_lat = float(statistics.quantiles(lat, n=20)[18]) if len(lat) >= 20 else (max(lat) if lat else 0.0)
        avg_cpu = float(statistics.fmean(counters.cpu_samples)) if counters.cpu_samples else 0.0
        avg_mem = float(statistics.fmean(counters.mem_samples_mb)) if counters.mem_samples_mb else 0.0
        pending_mb = counters.pending_upload_bytes / (1024 * 1024)

        result = StageResult(
            stage=stage,
            upload_limit_mbps=upload_limit_mbps,
            target_pps=target_pps,
            duration_s=duration_s,
            produced_packets=counters.produced_packets,
            dropped_packets=counters.dropped_packets,
            written_packets=counters.written_packets,
            written_bytes=counters.written_bytes,
            uploaded_bytes=counters.uploaded_bytes,
            upload_files=counters.upload_files,
            write_errors=counters.write_errors,
            upload_errors=counters.upload_errors,
            avg_write_latency_ms=avg_lat,
            p95_write_latency_ms=p95_lat,
            avg_cpu_pct=avg_cpu,
            avg_mem_mb=avg_mem,
            pending_upload_mb_end=pending_mb,
            degraded=False,
            degraded_reasons=[],
        )

    reasons: List[str] = []
    if result.drop_rate > drop_threshold:
        reasons.append(f"drop_rate>{drop_threshold:.3f}")
    if result.p95_write_latency_ms > latency_threshold_ms:
        reasons.append(f"p95_latency>{latency_threshold_ms:.1f}ms")
    if result.pending_upload_mb_end > pending_upload_threshold_mb:
        reasons.append(f"pending_upload>{pending_upload_threshold_mb:.1f}MB")
    if result.write_errors > 0:
        reasons.append("write_errors>0")
    if result.upload_errors > 0:
        reasons.append("upload_errors>0")

    result.degraded = len(reasons) > 0
    result.degraded_reasons = reasons
    return result


def _fmt_mode(limit: float) -> str:
    return "unlimited" if limit <= 0 else f"{limit:.0f} MB/s"


def run_load_test(args) -> tuple[List[StageResult], List[ModeSummary]]:
    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    upload_modes = _parse_upload_modes(args.upload_modes)
    all_results: List[StageResult] = []
    summaries: List[ModeSummary] = []
    stage_id = 1
    pps = max(1, int(args.start_pps))

    print(f"Output dir: {out_dir}")
    print(f"Test modes: {', '.join(_fmt_mode(m) for m in upload_modes)}")
    print(
        "Config: "
        f"duration={args.duration_s}s start_pps={args.start_pps} step_pps={args.step_pps} max_pps={args.max_pps} "
        f"packet_size={args.packet_size}B queue={args.queue_size} segment={args.segment_size_mb}MB "
        f"local_write_limit={args.local_write_limit_mbps}MB/s sink=simulated-local"
    )

    for mode in upload_modes:
        print(f"\nMode {_fmt_mode(mode)}")
        mode_max_sustainable = 0
        degraded_at: Optional[int] = None
        ran_any = False

        while True:
            probe_pps = min(pps, args.max_pps)
            if ran_any and pps > args.max_pps:
                break
            print(f"  Stage {stage_id}: target_pps={probe_pps}")
            r = run_stage(
                stage=stage_id,
                out_dir=out_dir,
                target_pps=probe_pps,
                duration_s=args.duration_s,
                packet_size=args.packet_size,
                queue_size=args.queue_size,
                segment_size_mb=args.segment_size_mb,
                upload_limit_mbps=mode,
                local_write_limit_mbps=args.local_write_limit_mbps,
                drop_threshold=args.drop_threshold,
                latency_threshold_ms=args.latency_threshold_ms,
                pending_upload_threshold_mb=args.pending_upload_threshold_mb,
            )
            all_results.append(r)
            ran_any = True
            status = "DEGRADED" if r.degraded else "OK"
            print(
                "    "
                f"{status} cap={r.capture_pps:.0f}pps disk={r.disk_mbps:.2f}MB/s upload={r.upload_mbps:.2f}MB/s "
                f"drop={r.drop_rate*100:.2f}% lat_avg={r.avg_write_latency_ms:.2f}ms "
                f"cpu={r.avg_cpu_pct:.1f}% mem={r.avg_mem_mb:.1f}MB pending={r.pending_upload_mb_end:.2f}MB"
            )
            if r.degraded:
                degraded_at = probe_pps
                if r.degraded_reasons:
                    print(f"    reasons: {', '.join(r.degraded_reasons)}")
                break
            mode_max_sustainable = probe_pps
            if probe_pps >= args.max_pps:
                break
            pps += args.step_pps
            stage_id += 1

        summaries.append(
            ModeSummary(
                upload_limit_mbps=mode,
                max_sustainable_pps=mode_max_sustainable,
                degraded_at_pps=degraded_at,
            )
        )
        # Continue ramping from next higher load even when degrading.
        pps += args.step_pps
        stage_id += 1

        if mode <= 1.0 and degraded_at is not None:
            break

    return all_results, summaries


def write_csv(path: Path, rows: List[StageResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "stage",
                "upload_limit_mbps",
                "target_pps",
                "capture_pps",
                "disk_mbps",
                "upload_mbps",
                "drop_rate",
                "avg_write_latency_ms",
                "p95_write_latency_ms",
                "avg_cpu_pct",
                "avg_mem_mb",
                "pending_upload_mb_end",
                "write_errors",
                "upload_errors",
                "degraded",
                "degraded_reasons",
            ]
        )
        for r in rows:
            writer.writerow(
                [
                    r.stage,
                    r.upload_limit_mbps,
                    r.target_pps,
                    f"{r.capture_pps:.2f}",
                    f"{r.disk_mbps:.4f}",
                    f"{r.upload_mbps:.4f}",
                    f"{r.drop_rate:.6f}",
                    f"{r.avg_write_latency_ms:.4f}",
                    f"{r.p95_write_latency_ms:.4f}",
                    f"{r.avg_cpu_pct:.2f}",
                    f"{r.avg_mem_mb:.2f}",
                    f"{r.pending_upload_mb_end:.4f}",
                    r.write_errors,
                    r.upload_errors,
                    int(r.degraded),
                    ";".join(r.degraded_reasons),
                ]
            )


def print_final_report(rows: List[StageResult], summaries: List[ModeSummary]) -> None:
    print("\nLoad evolution table")
    print("stage | mode       | target_pps | cap_pps | disk_mb/s | upload_mb/s | drop% | lat_ms | cpu% | mem_mb | degraded")
    print("------+------------+------------+---------+-----------+-------------+-------+--------+------+--------+---------")
    for r in rows:
        print(
            f"{r.stage:5d} | "
            f"{_fmt_mode(r.upload_limit_mbps):10} | "
            f"{r.target_pps:10d} | "
            f"{r.capture_pps:7.0f} | "
            f"{r.disk_mbps:9.2f} | "
            f"{r.upload_mbps:11.2f} | "
            f"{r.drop_rate*100:5.2f} | "
            f"{r.avg_write_latency_ms:6.2f} | "
            f"{r.avg_cpu_pct:4.1f} | "
            f"{r.avg_mem_mb:6.1f} | "
            f"{'YES' if r.degraded else 'NO'}"
        )

    print("\nFinal summary (requested 4 points)")
    print("mode        | max_sustainable_pps | degraded_at_pps")
    print("------------+---------------------+----------------")
    for s in summaries:
        deg = "-" if s.degraded_at_pps is None else str(s.degraded_at_pps)
        print(f"{_fmt_mode(s.upload_limit_mbps):11} | {s.max_sustainable_pps:19d} | {deg:14}")

    overall_max = max((s.max_sustainable_pps for s in summaries), default=0)
    first_degraded = next((r for r in rows if r.degraded), None)
    print("\nTechnical conclusion")
    print(f"- Maximum sustainable RTP ingress observed: {overall_max} pps")
    if first_degraded is not None:
        print(
            "- First clear degradation point: "
            f"mode={_fmt_mode(first_degraded.upload_limit_mbps)}, "
            f"target_pps={first_degraded.target_pps}, "
            f"reasons={','.join(first_degraded.degraded_reasons) or 'n/a'}"
        )
    else:
        print("- No degradation observed in tested range")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single E2E load test (local-only): RTP ingest -> local disk segments -> concurrent simulated S3 upload"
    )
    parser.add_argument("--start-pps", type=int, default=30000)
    parser.add_argument("--step-pps", type=int, default=5000)
    parser.add_argument("--max-pps", type=int, default=120000)
    parser.add_argument("--duration-s", type=int, default=10)
    parser.add_argument("--packet-size", type=int, default=220)
    parser.add_argument("--queue-size", type=int, default=50000)
    parser.add_argument("--segment-size-mb", type=int, default=1)
    parser.add_argument("--local-write-limit-mbps", type=float, default=1000.0)
    parser.add_argument(
        "--upload-modes",
        type=str,
        default="3,1,5,0",
        help="Comma-separated upload limits in MB/s; use 0 or 'unlimited' for no limit. Order defines test start/order.",
    )
    parser.add_argument("--drop-threshold", type=float, default=0.005)
    parser.add_argument("--latency-threshold-ms", type=float, default=50.0)
    parser.add_argument("--pending-upload-threshold-mb", type=float, default=5120.0)
    parser.add_argument(
        "--output-dir",
        default=str(Path("benchmarks") / "load_test" / dt.datetime.now(dt.UTC).strftime("%Y%m%d_%H%M%S")),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows, summaries = run_load_test(args)
    out_dir = Path(args.output_dir).expanduser().resolve()
    csv_path = out_dir / "load_test_results.csv"
    write_csv(csv_path, rows)
    print_final_report(rows, summaries)
    print(f"\nCSV written to: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
