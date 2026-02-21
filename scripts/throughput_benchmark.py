#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import queue
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rtphelper.rpcap.pcap_writer import RollingPcapWriter


@dataclass
class CaseResult:
    target_pps: int
    upload_limit_mbps: float
    produced_packets: int
    dropped_packets: int
    written_packets: int
    written_bytes: int
    uploaded_bytes: int
    elapsed_seconds: float
    max_capture_queue_depth: int
    spool_peak_bytes: int
    spool_end_bytes: int

    @property
    def drop_ratio(self) -> float:
        if self.produced_packets <= 0:
            return 0.0
        return float(self.dropped_packets) / float(self.produced_packets)

    @property
    def capture_pps(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.produced_packets / self.elapsed_seconds

    @property
    def write_pps(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.written_packets / self.elapsed_seconds

    @property
    def write_mbps(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return (self.written_bytes / (1024 * 1024)) / self.elapsed_seconds

    @property
    def upload_mbps(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return (self.uploaded_bytes / (1024 * 1024)) / self.elapsed_seconds

    @property
    def spool_growth_mbps(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return (self.spool_end_bytes / (1024 * 1024)) / self.elapsed_seconds


@dataclass
class SweepPoint:
    upload_limit_mbps: float
    max_stable_pps: int
    degraded_at_pps: int


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
        now_elapsed = time.perf_counter() - self._start
        if target_elapsed > now_elapsed:
            time.sleep(target_elapsed - now_elapsed)


def _parse_int_cases(raw: str) -> List[int]:
    out: List[int] = []
    for token in (raw or "").split(","):
        t = token.strip()
        if not t:
            continue
        out.append(max(1, int(t)))
    if not out:
        raise ValueError("No valid PPS cases were provided")
    return sorted(set(out))


def _parse_float_cases(raw: str) -> List[float]:
    out: List[float] = []
    for token in (raw or "").split(","):
        t = token.strip()
        if not t:
            continue
        out.append(max(0.0, float(t)))
    if not out:
        raise ValueError("No valid upload limits were provided")
    return sorted(set(out))


def run_case(
    out_dir: Path,
    target_pps: int,
    duration_seconds: int,
    packet_size: int,
    queue_size: int,
    local_write_limit_mbps: float,
    upload_limit_mbps: float,
    spool_max_mb: int,
    linktype: int,
    snaplen: int,
) -> CaseResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    writer = RollingPcapWriter(
        base_dir=out_dir,
        file_prefix=f"bench-u{str(upload_limit_mbps).replace('.', '_')}-{target_pps}pps",
        max_bytes=2 * 1024 * 1024 * 1024,
        linktype=linktype,
        snaplen=snaplen,
    )

    payload = (b"RTPHELPERBENCH" * ((packet_size // 13) + 1))[:packet_size]
    capture_q: "queue.Queue[tuple[int, int, bytes, int]]" = queue.Queue(maxsize=queue_size)
    producer_done = threading.Event()
    writer_done = threading.Event()
    stop_due_spool = threading.Event()

    produced = 0
    dropped = 0
    written = 0
    written_bytes = 0
    uploaded_bytes = 0
    max_depth = 0
    spool_pending_bytes = 0
    spool_peak_bytes = 0
    spool_max_bytes = max(1, spool_max_mb) * 1024 * 1024
    lock = threading.Lock()

    upload_limiter = RateLimiter(upload_limit_mbps * 1024 * 1024) if upload_limit_mbps > 0 else None
    local_write_limiter = RateLimiter(local_write_limit_mbps * 1024 * 1024) if local_write_limit_mbps > 0 else None

    def producer() -> None:
        nonlocal produced, dropped, max_depth
        start = time.perf_counter()
        next_tick = start
        interval = 1.0 / float(target_pps)
        while True:
            now = time.perf_counter()
            if now - start >= duration_seconds:
                break
            if stop_due_spool.is_set():
                break
            if now < next_tick:
                time.sleep(next_tick - now)
                continue
            wall = time.time()
            ts_sec = int(wall)
            ts_usec = int((wall - ts_sec) * 1_000_000)
            with lock:
                produced += 1
            try:
                capture_q.put_nowait((ts_sec, ts_usec, payload, packet_size))
                with lock:
                    depth = capture_q.qsize()
                    if depth > max_depth:
                        max_depth = depth
            except queue.Full:
                with lock:
                    dropped += 1
            next_tick += interval
        producer_done.set()

    def writer_consumer() -> None:
        nonlocal written, written_bytes, spool_pending_bytes, spool_peak_bytes
        while True:
            if producer_done.is_set() and capture_q.empty():
                break
            try:
                ts_sec, ts_usec, data, orig_len = capture_q.get(timeout=0.1)
            except queue.Empty:
                continue
            if local_write_limiter is not None:
                local_write_limiter.wait_for(len(data) + 16)
            writer.write_packet(ts_sec, ts_usec, data, orig_len)
            rec_bytes = len(data) + 16
            with lock:
                written += 1
                written_bytes += rec_bytes
                spool_pending_bytes += rec_bytes
                if spool_pending_bytes > spool_peak_bytes:
                    spool_peak_bytes = spool_pending_bytes
                if spool_pending_bytes >= spool_max_bytes:
                    stop_due_spool.set()
            capture_q.task_done()
        writer.close()
        writer_done.set()

    def uploader() -> None:
        nonlocal uploaded_bytes, spool_pending_bytes
        if upload_limiter is None:
            return
        while True:
            with lock:
                pending = spool_pending_bytes
            if writer_done.is_set():
                break
            if pending <= 0:
                time.sleep(0.02)
                continue
            chunk = min(pending, 128 * 1024)
            upload_limiter.wait_for(chunk)
            with lock:
                drain = min(chunk, spool_pending_bytes)
                spool_pending_bytes -= drain
                uploaded_bytes += drain

    t0 = time.perf_counter()
    t_prod = threading.Thread(target=producer, name=f"bench-prod-{target_pps}", daemon=True)
    t_wri = threading.Thread(target=writer_consumer, name=f"bench-wri-{target_pps}", daemon=True)
    t_up = threading.Thread(target=uploader, name=f"bench-up-{target_pps}", daemon=True)
    t_prod.start()
    t_wri.start()
    t_up.start()
    t_prod.join()
    t_wri.join()
    t_up.join()
    elapsed = time.perf_counter() - t0

    with lock:
        spool_end_bytes = spool_pending_bytes

    return CaseResult(
        target_pps=target_pps,
        upload_limit_mbps=upload_limit_mbps,
        produced_packets=produced,
        dropped_packets=dropped,
        written_packets=written,
        written_bytes=written_bytes,
        uploaded_bytes=uploaded_bytes,
        elapsed_seconds=elapsed,
        max_capture_queue_depth=max_depth,
        spool_peak_bytes=spool_peak_bytes,
        spool_end_bytes=spool_end_bytes,
    )


def _is_sustainable(
    result: CaseResult,
    drop_threshold: float,
    growth_threshold_mbps: float,
    upload_limit_mbps: float | None = None,
) -> bool:
    if upload_limit_mbps is None:
        upload_limit_mbps = result.upload_limit_mbps
    if upload_limit_mbps <= 0:
        return result.drop_ratio <= drop_threshold
    return result.drop_ratio <= drop_threshold and result.spool_growth_mbps <= growth_threshold_mbps


def _run_and_check(
    *,
    out_dir: Path,
    upload_limit_mbps: float,
    target_pps: int,
    duration_seconds: int,
    packet_size: int,
    queue_size: int,
    local_write_limit_mbps: float,
    spool_max_mb: int,
    linktype: int,
    snaplen: int,
    drop_threshold: float,
    growth_threshold_mbps: float,
) -> tuple[CaseResult, bool]:
    result = run_case(
        out_dir=out_dir,
        target_pps=target_pps,
        duration_seconds=duration_seconds,
        packet_size=packet_size,
        queue_size=queue_size,
        local_write_limit_mbps=local_write_limit_mbps,
        upload_limit_mbps=upload_limit_mbps,
        spool_max_mb=spool_max_mb,
        linktype=linktype,
        snaplen=snaplen,
    )
    return result, _is_sustainable(
        result,
        drop_threshold,
        growth_threshold_mbps,
        upload_limit_mbps=upload_limit_mbps,
    )


def _find_max_stable_pps(
    *,
    out_dir: Path,
    upload_limit_mbps: float,
    pps_min: int,
    pps_max: int,
    coarse_step: int,
    duration_seconds: int,
    packet_size: int,
    queue_size: int,
    local_write_limit_mbps: float,
    spool_max_mb: int,
    linktype: int,
    snaplen: int,
    drop_threshold: float,
    growth_threshold_mbps: float,
) -> SweepPoint:
    last_ok = 0
    first_bad = 0

    p = max(pps_min, 1)
    while p <= pps_max:
        result, ok = _run_and_check(
            out_dir=out_dir,
            upload_limit_mbps=upload_limit_mbps,
            target_pps=p,
            duration_seconds=duration_seconds,
            packet_size=packet_size,
            queue_size=queue_size,
            local_write_limit_mbps=local_write_limit_mbps,
            spool_max_mb=spool_max_mb,
            linktype=linktype,
            snaplen=snaplen,
            drop_threshold=drop_threshold,
            growth_threshold_mbps=growth_threshold_mbps,
        )
        status = "OK" if ok else "DEGRADED"
        print(
            f"  probe upload={upload_limit_mbps:.2f}MB/s pps={p} "
            f"=> {status} (write={result.write_mbps:.2f}MB/s upload={result.upload_mbps:.2f}MB/s "
            f"spool_end={result.spool_end_bytes/(1024*1024):.2f}MB drop={result.drop_ratio*100:.2f}%)"
        )
        if ok:
            last_ok = p
            p += coarse_step
            continue
        first_bad = p
        break

    if first_bad == 0:
        return SweepPoint(upload_limit_mbps=upload_limit_mbps, max_stable_pps=last_ok, degraded_at_pps=0)
    if last_ok == 0:
        return SweepPoint(upload_limit_mbps=upload_limit_mbps, max_stable_pps=0, degraded_at_pps=first_bad)

    lo = last_ok + 1
    hi = first_bad - 1
    best = last_ok
    while lo <= hi:
        mid = (lo + hi) // 2
        _, ok = _run_and_check(
            out_dir=out_dir,
            upload_limit_mbps=upload_limit_mbps,
            target_pps=mid,
            duration_seconds=duration_seconds,
            packet_size=packet_size,
            queue_size=queue_size,
            local_write_limit_mbps=local_write_limit_mbps,
            spool_max_mb=spool_max_mb,
            linktype=linktype,
            snaplen=snaplen,
            drop_threshold=drop_threshold,
            growth_threshold_mbps=growth_threshold_mbps,
        )
        if ok:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return SweepPoint(upload_limit_mbps=upload_limit_mbps, max_stable_pps=best, degraded_at_pps=first_bad)


def _print_group(
    upload_limit_mbps: float,
    results: Iterable[CaseResult],
    drop_threshold: float,
    growth_threshold_mbps: float,
) -> None:
    print(f"\nUpload limit: {upload_limit_mbps:.2f} MB/s")
    print("target_pps | cap_pps | write_mb/s | upload_mb/s | spool_end_mb | drop% | status")
    print("-----------+---------+------------+-------------+--------------+-------+--------")
    best: CaseResult | None = None
    for r in results:
        status = (
            "OK"
            if _is_sustainable(
                r,
                drop_threshold,
                growth_threshold_mbps,
                upload_limit_mbps=upload_limit_mbps,
            )
            else "NOK"
        )
        print(
            f"{r.target_pps:10d} | "
            f"{r.capture_pps:7.0f} | "
            f"{r.write_mbps:10.2f} | "
            f"{r.upload_mbps:11.2f} | "
            f"{(r.spool_end_bytes/(1024*1024)):12.2f} | "
            f"{r.drop_ratio*100:5.2f} | {status}"
        )
        if status == "OK":
            if best is None or r.target_pps > best.target_pps:
                best = r
    if best is None:
        print("=> No sustainable case found")
    else:
        print(f"=> Max sustainable capture PPS at {upload_limit_mbps:.2f} MB/s: {best.target_pps}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture+local-spool+concurrent-upload benchmark (no rpcapd, no real S3)"
    )
    parser.add_argument("--pps", type=int, default=0, help="Optional single target PPS case")
    parser.add_argument("--cases-pps", default="1000,2500,5000,10000,20000,30000,40000")
    parser.add_argument("--duration-seconds", type=int, default=10)
    parser.add_argument("--packet-size", type=int, default=220)
    parser.add_argument("--queue-size", type=int, default=20000)
    parser.add_argument(
        "--local-write-limit-mbps",
        type=float,
        default=1000.0,
        help="Local disk write throttle in MB/s (default: 1000)",
    )
    parser.add_argument("--upload-limit-mbps", type=float, default=0.0, help="Single upload limit")
    parser.add_argument("--upload-limits-mbps", default="", help="Comma-separated upload limits (e.g. 1,5)")
    parser.add_argument(
        "--auto-sweep",
        action="store_true",
        help="Adaptive degradation sweep: unlimited -> 5 -> 3 -> 1 MB/s",
    )
    parser.add_argument("--auto-min-pps", type=int, default=10000, help="Minimum PPS for auto sweep")
    parser.add_argument("--auto-max-pps", type=int, default=80000, help="Maximum PPS for auto sweep")
    parser.add_argument("--auto-step-pps", type=int, default=5000, help="Coarse PPS step for auto sweep")
    parser.add_argument("--spool-max-mb", type=int, default=5120, help="Local spool cap in MB")
    parser.add_argument("--drop-threshold", type=float, default=0.01)
    parser.add_argument(
        "--growth-threshold-mbps",
        type=float,
        default=0.05,
        help="Sustainable if final spool growth <= threshold MB/s",
    )
    parser.add_argument("--linktype", type=int, default=1)
    parser.add_argument("--snaplen", type=int, default=262144)
    parser.add_argument(
        "--output-dir",
        default=str(Path("benchmarks") / "throughput" / dt.datetime.now(dt.UTC).strftime("%Y%m%d_%H%M%S")),
    )
    args = parser.parse_args()

    if args.auto_sweep:
        pps_cases = []
        upload_limits = [0.0, 5.0, 3.0, 1.0]
    else:
        if int(args.pps or 0) > 0:
            pps_cases = [int(args.pps)]
        else:
            pps_cases = _parse_int_cases(args.cases_pps)

        if str(args.upload_limits_mbps or "").strip():
            upload_limits = _parse_float_cases(args.upload_limits_mbps)
        else:
            upload_limits = [max(0.0, float(args.upload_limit_mbps))]

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output dir: {out_dir}")
    if pps_cases:
        print(f"PPS cases: {pps_cases}")
    print(f"Upload limits MB/s: {upload_limits}")
    print(
        "Config: "
        f"duration={args.duration_seconds}s packet_size={args.packet_size}B "
        f"queue={args.queue_size} spool_max={args.spool_max_mb}MB "
        f"local_write_limit={args.local_write_limit_mbps:.2f}MB/s"
    )

    if args.auto_sweep:
        print("\nAdaptive degradation sweep")
        points: List[SweepPoint] = []
        for upload_limit in upload_limits:
            label = "unlimited" if upload_limit <= 0 else f"{upload_limit:.0f}MB/s"
            print(f"\nSweep for upload={label}")
            point = _find_max_stable_pps(
                out_dir=out_dir,
                upload_limit_mbps=upload_limit,
                pps_min=max(1, int(args.auto_min_pps)),
                pps_max=max(int(args.auto_min_pps), int(args.auto_max_pps)),
                coarse_step=max(500, int(args.auto_step_pps)),
                duration_seconds=max(1, int(args.duration_seconds)),
                packet_size=max(64, int(args.packet_size)),
                queue_size=max(1000, int(args.queue_size)),
                local_write_limit_mbps=max(0.0, float(args.local_write_limit_mbps)),
                spool_max_mb=max(64, int(args.spool_max_mb)),
                linktype=max(1, int(args.linktype)),
                snaplen=max(64, int(args.snaplen)),
                drop_threshold=max(0.0, min(1.0, float(args.drop_threshold))),
                growth_threshold_mbps=max(0.0, float(args.growth_threshold_mbps)),
            )
            points.append(point)

        print("\nFinal comparison table")
        print("mode        | max_stable_pps | degraded_at_pps")
        print("------------+----------------+----------------")
        for p in points:
            mode = "unlimited" if p.upload_limit_mbps <= 0 else f"{p.upload_limit_mbps:.0f} MB/s"
            degraded = "-" if p.degraded_at_pps <= 0 else str(p.degraded_at_pps)
            print(f"{mode:11} | {p.max_stable_pps:14d} | {degraded:14}")
    else:
        all_results: dict[float, List[CaseResult]] = {u: [] for u in upload_limits}
        for upload_limit in upload_limits:
            for pps in pps_cases:
                print(f"\nRunning case upload={upload_limit:.2f}MB/s target_pps={pps} ...")
                r = run_case(
                    out_dir=out_dir,
                    target_pps=max(1, int(pps)),
                    duration_seconds=max(1, int(args.duration_seconds)),
                    packet_size=max(64, int(args.packet_size)),
                    queue_size=max(1000, int(args.queue_size)),
                    local_write_limit_mbps=max(0.0, float(args.local_write_limit_mbps)),
                    upload_limit_mbps=max(0.0, float(upload_limit)),
                    spool_max_mb=max(64, int(args.spool_max_mb)),
                    linktype=max(1, int(args.linktype)),
                    snaplen=max(64, int(args.snaplen)),
                )
                all_results[upload_limit].append(r)

        print("\nCapture vs Upload benchmark results")
        for upload_limit in upload_limits:
            _print_group(
                upload_limit_mbps=upload_limit,
                results=all_results[upload_limit],
                drop_threshold=max(0.0, min(1.0, float(args.drop_threshold))),
                growth_threshold_mbps=max(0.0, float(args.growth_threshold_mbps)),
            )

        if len(upload_limits) >= 2:
            print("\nSummary by upload limit")
            for upload_limit in upload_limits:
                best = None
                for r in all_results[upload_limit]:
                    if _is_sustainable(
                        r,
                        args.drop_threshold,
                        args.growth_threshold_mbps,
                        upload_limit_mbps=upload_limit,
                    ):
                        if best is None or r.target_pps > best.target_pps:
                            best = r
                if best is None:
                    print(f"- {upload_limit:.2f} MB/s => no sustainable PPS found")
                else:
                    print(f"- {upload_limit:.2f} MB/s => {best.target_pps} pps sustainable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
