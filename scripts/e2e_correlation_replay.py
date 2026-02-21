#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import importlib
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"

EXPECTED_PREFIXES = {
    "direction": "INFO: Direction:",
    "packet_selection": "INFO: Packet selection ",
    "negotiation_context": "INFO: Negotiation context ",
    "carrier_rtp": "INFO: Carrier request/reply RTP from SIP m=audio:",
    "core_rtp": "INFO: Core request/reply RTP from SIP m=audio:",
    "processed_filtered": "INFO: Processed filtered files:",
}


@dataclass
class Scenario:
    name: str
    direction: str | None
    source_dir: Path
    work_dir: Path | None = None
    expected_lines: dict[str, str] | None = None


@dataclass
class TestOutcome:
    name: str
    passed: bool
    details: str


def _must_exist_dir(path: Path, label: str) -> None:
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"{label} does not exist or is not a directory: {path}")


def _find_single(path: Path, pattern: str, label: str) -> Path:
    matches = sorted(path.glob(pattern))
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly 1 {label} in {path} (pattern={pattern}), found {len(matches)}")
    return matches[0]


def _read_reference_lines(log_file: Path) -> dict[str, str]:
    lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    found: dict[str, str] = {}
    for key, prefix in EXPECTED_PREFIXES.items():
        for line in lines:
            pos = line.find(prefix)
            if pos >= 0:
                found[key] = line[pos:].strip()
                break
    missing = [k for k in EXPECTED_PREFIXES if k not in found]
    if missing:
        raise SystemExit(f"Missing expected markers in reference log {log_file}: {', '.join(missing)}")
    return found


def _prepare_scenario_copy(scenario: Scenario, sandbox_root: Path) -> None:
    scenario_dir = sandbox_root / scenario.name
    scenario_dir.mkdir(parents=True, exist_ok=True)
    raw_src = scenario.source_dir / "raw"
    uploads_src = scenario.source_dir / "uploads"
    log_src = _find_single(scenario.source_dir, "rtp-capture-tool-logs-*.txt", "reference log file")
    _must_exist_dir(raw_src, f"{scenario.name}/raw")
    _must_exist_dir(uploads_src, f"{scenario.name}/uploads")

    raw_dst = scenario_dir / "raw"
    uploads_dst = scenario_dir / "uploads"
    raw_dst.mkdir(parents=True, exist_ok=True)
    uploads_dst.mkdir(parents=True, exist_ok=True)

    for src in sorted(raw_src.glob("*.pcap*")):
        shutil.copy2(src, raw_dst / src.name)
    for src in sorted(uploads_src.glob("*.pcap*")):
        shutil.copy2(src, uploads_dst / src.name)
    shutil.copy2(log_src, scenario_dir / log_src.name)

    scenario.work_dir = scenario_dir
    scenario.expected_lines = _read_reference_lines(scenario_dir / log_src.name)
    direction_line = scenario.expected_lines.get("direction", "")
    m = re.search(r"INFO: Direction:\s*([A-Za-z]+)", direction_line)
    if not m:
        raise SystemExit(f"Could not infer call direction from reference log line: {direction_line}")
    scenario.direction = m.group(1).strip().lower()
    if scenario.direction not in {"inbound", "outbound"}:
        raise SystemExit(f"Unsupported direction '{scenario.direction}' in scenario {scenario.name}")


def _is_case_timestamp_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    if not (path / "raw").is_dir():
        return False
    if not (path / "uploads").is_dir():
        return False
    return len(list(path.glob("rtp-capture-tool-logs-*.txt"))) == 1


def _resolve_case_source_dir(case_dir: Path) -> Path:
    if _is_case_timestamp_dir(case_dir):
        return case_dir
    candidates = sorted([p for p in case_dir.iterdir() if _is_case_timestamp_dir(p)], key=lambda p: p.name, reverse=True)
    if not candidates:
        raise SystemExit(
            f"Case '{case_dir.name}' has no valid timestamp directory. "
            "Expected raw/, uploads/, and one rtp-capture-tool-logs-*.txt"
        )
    return candidates[0]


def _discover_scenarios(cases_root: Path) -> list[Scenario]:
    case_dirs = sorted([p for p in cases_root.iterdir() if p.is_dir()])
    if not case_dirs:
        raise SystemExit(f"No test case directories found in {cases_root}")
    scenarios: list[Scenario] = []
    for case_dir in case_dirs:
        source_dir = _resolve_case_source_dir(case_dir)
        scenarios.append(Scenario(name=case_dir.name, direction=None, source_dir=source_dir.resolve()))
    return scenarios


def _extract_actual_line(lines: list[str], prefix: str) -> str:
    for line in lines:
        if line.startswith(prefix):
            return line.strip()
    raise AssertionError(f"Missing line in response log_tail: {prefix}")


def _normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _assert_line_equal(expected: str, actual: str, key: str) -> None:
    if _normalize_spaces(expected) != _normalize_spaces(actual):
        raise AssertionError(f"[{key}] mismatch\nEXPECTED: {expected}\nACTUAL:   {actual}")


def _assert_processed_filtered_line(actual: str, scenario_name: str) -> None:
    m = re.search(r"decrypted=(\d+)\s+no-decrypt-need=(\d+)\s+total=(\d+)", actual)
    if not m:
        raise AssertionError(f"[{scenario_name}] invalid processed_filtered line format: {actual}")
    decrypted = int(m.group(1))
    no_decrypt = int(m.group(2))
    total = int(m.group(3))
    if total != decrypted + no_decrypt:
        raise AssertionError(
            f"[{scenario_name}] processed_filtered total mismatch: decrypted={decrypted} "
            f"no-decrypt-need={no_decrypt} total={total}"
        )
    if total < 1:
        raise AssertionError(f"[{scenario_name}] processed_filtered total must be >= 1 (actual={total})")


def _make_upload_file(path: Path):
    from fastapi import UploadFile

    payload = path.read_bytes()
    return UploadFile(filename=path.name, file=BytesIO(payload))


def _import_media(web_module: Any, scenario: Scenario) -> dict[str, Any]:
    assert scenario.work_dir is not None
    raw_dir = scenario.work_dir / "raw"
    upload_files = []
    try:
        for pcap in sorted(raw_dir.glob("*.pcap*")):
            upload_files.append(_make_upload_file(pcap))
        if not upload_files:
            raise AssertionError(f"No raw pcap files found in {raw_dir}")
        data = asyncio.run(
            web_module.import_capture(
                output_dir_name=f"e2e-{scenario.name}",
                media_files=upload_files,
            )
        )
    finally:
        for uf in upload_files:
            try:
                uf.file.close()
            except Exception:
                pass
    if not data.get("session_id"):
        raise AssertionError(f"Import returned no session_id ({scenario.name})")
    return data


def _run_correlation(web_module: Any, scenario: Scenario) -> dict[str, Any]:
    assert scenario.work_dir is not None
    assert scenario.direction is not None
    sip_pcap = _find_single(scenario.work_dir / "uploads", "*.pcap*", "SIP pcap")
    upload = _make_upload_file(sip_pcap)
    try:
        data = asyncio.run(
            web_module.correlate(
                sip_pcap=upload,
                call_direction=scenario.direction,
                debug="0",
            )
        )
    finally:
        try:
            upload.file.close()
        except Exception:
            pass
    return data


def _validate_response(web_module: Any, scenario: Scenario, response_json: dict[str, Any]) -> None:
    assert scenario.expected_lines is not None
    log_tail = [str(x) for x in response_json.get("log_tail", [])]
    for key, expected_line in scenario.expected_lines.items():
        actual = _extract_actual_line(log_tail, EXPECTED_PREFIXES[key])
        if key == "processed_filtered":
            _assert_processed_filtered_line(actual, scenario.name)
            continue
        _assert_line_equal(expected_line, actual, key)

    if not bool(response_json.get("encrypted_likely")):
        raise AssertionError(f"[{scenario.name}] expected encrypted_likely=true")

    final_files = response_json.get("final_files") or {}
    required = ("encrypted_media", "decrypted_media", "sip_plus_decrypted_media")
    for name in required:
        url = final_files.get(name)
        if not url:
            raise AssertionError(f"[{scenario.name}] final_files.{name} is missing")
        m = re.match(r"^/downloads/([^/]+)/([^/]+)/(.+)$", str(url))
        if not m:
            raise AssertionError(f"[{scenario.name}] invalid download URL for {name}: {url}")
        session_id, kind, filename = m.group(1), m.group(2), m.group(3)
        dl = web_module.download_file(session_id=session_id, kind=kind, filename=filename)
        if not getattr(dl, "path", None):
            raise AssertionError(f"[{scenario.name}] download path missing for {name}: {url}")
        if not Path(dl.path).exists():
            raise AssertionError(f"[{scenario.name}] download file does not exist for {name}: {dl.path}")


def _build_web_module(capture_root: Path):
    os.environ["RTPHELPER_CAPTURE_ROOT"] = str(capture_root)
    module_name = "rtphelper.web.app"
    if module_name in sys.modules:
        importlib.reload(sys.modules[module_name])
        mod = sys.modules[module_name]
    else:
        mod = importlib.import_module(module_name)
    return mod


def _run_scenario(web_module: Any, scenario: Scenario) -> tuple[bool, str]:
    try:
        _import_media(web_module, scenario)
        response = _run_correlation(web_module, scenario)
        _validate_response(web_module, scenario, response)
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _colorize(text: str, ok: bool) -> str:
    color = ANSI_GREEN if ok else ANSI_RED
    return f"{color}{text}{ANSI_RESET}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay correlation from saved e2e cases and validate output against each case reference log."
    )
    parser.add_argument(
        "--cases-root",
        type=Path,
        default=Path("e2e-tests"),
        help=(
            "Root directory containing one subdirectory per test case. "
            "Each case may be a timestamp dir itself or include timestamp subdirs."
        ),
    )
    parser.add_argument(
        "--sandbox-root",
        type=Path,
        default=None,
        help="Optional temp root (default: auto temp dir). Files are copied here; captures/ is not modified.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    _must_exist_dir(args.cases_root, "E2E cases root")

    if args.sandbox_root:
        sandbox_root = args.sandbox_root.resolve()
        sandbox_root.mkdir(parents=True, exist_ok=True)
    else:
        sandbox_root = Path(tempfile.mkdtemp(prefix="rtphelper-e2e-"))

    replay_root = sandbox_root / "replay_inputs"
    capture_root = sandbox_root / "replay_capture_root"
    replay_root.mkdir(parents=True, exist_ok=True)
    capture_root.mkdir(parents=True, exist_ok=True)

    scenarios = _discover_scenarios(args.cases_root.resolve())

    for scenario in scenarios:
        print(f"Discovered case: {scenario.name} -> {scenario.source_dir}")
        _prepare_scenario_copy(scenario, replay_root)

    web_module = _build_web_module(capture_root)

    failed = False
    outcomes: list[TestOutcome] = []
    print(f"Sandbox root: {sandbox_root}")
    print(f"Replay inputs copied to: {replay_root}")
    print(f"Capture output root: {capture_root}")
    print("")
    for scenario in scenarios:
        ok, info = _run_scenario(web_module, scenario)
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {scenario.name}: {info}")
        outcomes.append(TestOutcome(name=scenario.name, passed=ok, details=info))
        failed = failed or (not ok)

    print("")
    print("Test results:")
    for outcome in outcomes:
        status = _colorize("[ OK ]", True) if outcome.passed else _colorize("[ NOK ]", False)
        print(f"- {outcome.name} - {status}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
