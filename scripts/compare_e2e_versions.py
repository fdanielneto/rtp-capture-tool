#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class VersionResult:
    label: str
    ref: str
    worktree_dir: Path
    metrics_path: Path
    metrics: dict[str, Any]
    return_code: int


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )


def _must_ok(proc: subprocess.CompletedProcess[str], what: str) -> None:
    if proc.returncode == 0:
        return
    raise SystemExit(
        f"{what} failed with exit={proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


def _summary(metrics: dict[str, Any]) -> dict[str, float]:
    s = metrics.get("summary", {})
    return {
        "total_correlation_seconds": float(s.get("total_correlation_seconds") or 0.0),
        "capture_root_total_disk_bytes": float(s.get("capture_root_total_disk_bytes") or 0.0),
        "capture_root_peak_disk_bytes": float(s.get("capture_root_peak_disk_bytes") or 0.0),
        "failed": float(s.get("failed") or 0.0),
    }


def _fmt_delta(candidate: float, baseline: float, lower_is_better: bool) -> str:
    diff = candidate - baseline
    pct = (diff / baseline * 100.0) if baseline else 0.0
    sign = "+" if diff >= 0 else "-"
    better = (diff < 0) if lower_is_better else (diff > 0)
    verdict = "better" if better else ("equal" if abs(diff) < 1e-12 else "worse")
    return f"{sign}{abs(diff):.3f} ({sign}{abs(pct):.2f}%) => {verdict}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Run E2E replay tests on two git refs and compare correlation time and local disk usage."
        )
    )
    p.add_argument("--baseline-ref", required=True, help="Git ref for baseline (e.g. main)")
    p.add_argument("--candidate-ref", required=True, help="Git ref for candidate (e.g. HEAD)")
    p.add_argument("--cases-root", type=Path, default=Path("e2e-tests"), help="Path to local E2E cases")
    p.add_argument(
        "--python-bin",
        default=str(PROJECT_ROOT / ".venv" / "bin" / "python"),
        help="Python interpreter used to run replay script",
    )
    p.add_argument(
        "--out-json",
        type=Path,
        default=Path("benchmarks") / "e2e_version_compare.json",
        help="Output JSON report path",
    )
    p.add_argument(
        "--keep-worktrees",
        action="store_true",
        help="Do not remove temporary git worktrees after execution",
    )
    return p.parse_args()


def _run_for_ref(
    root: Path,
    worktree_root: Path,
    ref: str,
    label: str,
    python_bin: str,
    cases_root: Path,
) -> VersionResult:
    wt = worktree_root / label
    add = _run(["git", "worktree", "add", "--detach", str(wt), ref], cwd=root)
    _must_ok(add, f"git worktree add ({label})")

    # Ensure local, non-versioned runtime config files are available in the detached worktree.
    src_hosts = root / "config" / "hosts.yaml"
    dst_hosts = wt / "config" / "hosts.yaml"
    if src_hosts.exists() and not dst_hosts.exists():
        dst_hosts.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_hosts, dst_hosts)
    src_env = root / "config" / "runtime.env"
    dst_env = wt / "config" / "runtime.env"
    if src_env.exists() and not dst_env.exists():
        dst_env.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_env, dst_env)

    runner_src = root / "scripts" / "e2e_correlation_replay.py"
    runner_dst = wt / "logs" / "e2e_correlation_replay_compare.py"
    runner_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(runner_src, runner_dst)
    metrics = wt / "logs" / f"e2e_metrics_{label}.json"
    sandbox = wt / "logs" / f"e2e_sandbox_{label}"
    cmd = [
        python_bin,
        str(runner_dst),
        "--cases-root",
        str(cases_root),
        "--sandbox-root",
        str(sandbox),
        "--metrics-json",
        str(metrics),
    ]
    proc = _run(cmd, cwd=wt)
    if proc.stdout:
        print(f"\n[{label}] replay stdout:\n{proc.stdout}")
    if proc.stderr:
        print(f"\n[{label}] replay stderr:\n{proc.stderr}")
    if proc.returncode != 0:
        raise SystemExit(f"E2E replay failed for {label} ({ref}) with exit={proc.returncode}")
    if not metrics.exists():
        raise SystemExit(f"Metrics file not generated for {label}: {metrics}")
    return VersionResult(
        label=label,
        ref=ref,
        worktree_dir=wt,
        metrics_path=metrics,
        metrics=json.loads(metrics.read_text(encoding="utf-8")),
        return_code=proc.returncode,
    )


def main() -> int:
    args = parse_args()
    root = PROJECT_ROOT.resolve()
    cases_root = args.cases_root.resolve()
    if not cases_root.is_dir():
        raise SystemExit(f"cases-root does not exist or is not a directory: {cases_root}")
    if not Path(args.python_bin).exists():
        raise SystemExit(f"python-bin not found: {args.python_bin}")

    temp_root = Path(tempfile.mkdtemp(prefix="rtphelper-e2e-compare-"))
    baseline: VersionResult | None = None
    candidate: VersionResult | None = None

    try:
        baseline = _run_for_ref(
            root=root,
            worktree_root=temp_root,
            ref=args.baseline_ref,
            label="baseline",
            python_bin=args.python_bin,
            cases_root=cases_root,
        )
        candidate = _run_for_ref(
            root=root,
            worktree_root=temp_root,
            ref=args.candidate_ref,
            label="candidate",
            python_bin=args.python_bin,
            cases_root=cases_root,
        )
    finally:
        if not args.keep_worktrees:
            for label in ("baseline", "candidate"):
                wt = temp_root / label
                if wt.exists():
                    _run(["git", "worktree", "remove", "--force", str(wt)], cwd=root)
            shutil.rmtree(temp_root, ignore_errors=True)

    if baseline is None or candidate is None:
        raise SystemExit("Could not execute both baseline and candidate runs")

    b = _summary(baseline.metrics)
    c = _summary(candidate.metrics)
    report = {
        "baseline": {
            "ref": baseline.ref,
            "metrics_path": str(baseline.metrics_path),
            "summary": baseline.metrics.get("summary", {}),
        },
        "candidate": {
            "ref": candidate.ref,
            "metrics_path": str(candidate.metrics_path),
            "summary": candidate.metrics.get("summary", {}),
        },
        "comparison": {
            "correlation_time_delta_seconds": c["total_correlation_seconds"] - b["total_correlation_seconds"],
            "disk_total_delta_bytes": c["capture_root_total_disk_bytes"] - b["capture_root_total_disk_bytes"],
            "disk_peak_delta_bytes": c["capture_root_peak_disk_bytes"] - b["capture_root_peak_disk_bytes"],
        },
    }

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nComparison summary")
    print(f"- baseline ref:  {baseline.ref}")
    print(f"- candidate ref: {candidate.ref}")
    print(
        "- total correlation time: "
        f"baseline={b['total_correlation_seconds']:.3f}s "
        f"candidate={c['total_correlation_seconds']:.3f}s "
        f"delta={_fmt_delta(c['total_correlation_seconds'], b['total_correlation_seconds'], lower_is_better=True)}"
    )
    print(
        "- local disk total: "
        f"baseline={int(b['capture_root_total_disk_bytes'])}B "
        f"candidate={int(c['capture_root_total_disk_bytes'])}B "
        f"delta={_fmt_delta(c['capture_root_total_disk_bytes'], b['capture_root_total_disk_bytes'], lower_is_better=True)}"
    )
    print(
        "- local disk peak: "
        f"baseline={int(b['capture_root_peak_disk_bytes'])}B "
        f"candidate={int(c['capture_root_peak_disk_bytes'])}B "
        f"delta={_fmt_delta(c['capture_root_peak_disk_bytes'], b['capture_root_peak_disk_bytes'], lower_is_better=True)}"
    )
    print(f"\nReport JSON: {args.out_json.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
