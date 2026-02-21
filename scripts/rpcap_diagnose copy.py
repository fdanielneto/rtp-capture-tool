#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import platform
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from rtphelper.logging_setup import correlation_context, setup_logging, short_uuid

DEFAULT_PORT = 2002
CONNECT_TIMEOUT_SECONDS = 3.0
DUMPCAP_TIMEOUT_SECONDS = 12.0
PREFLIGHT_CAPTURE_SECONDS = 1
LOGGER = logging.getLogger(__name__)


@dataclass
class CheckResult:
    ok: bool
    title: str
    details: str = ""


def _run(cmd: List[str], timeout: float) -> Tuple[int, str, str]:
    LOGGER.debug("diag run cmd=%s timeout=%s", cmd, timeout, extra={"category": "PERF"})
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    LOGGER.debug(
        "diag run completed cmd=%s rc=%s stdout_len=%s stderr_len=%s",
        cmd,
        proc.returncode,
        len(proc.stdout or ""),
        len(proc.stderr or ""),
        extra={"category": "PERF"},
    )
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def check_macos_arm64() -> CheckResult:
    sysname = platform.system()
    machine = platform.machine()
    if sysname != "Darwin":
        LOGGER.warning("diag unsupported platform=%s", sysname, extra={"category": "CONFIG"})
        return CheckResult(False, "Platform", f"Expected macOS (Darwin), got {sysname}")
    if machine != "arm64":
        LOGGER.warning("diag unsupported arch=%s", machine, extra={"category": "CONFIG"})
        return CheckResult(False, "Architecture", f"Expected arm64 (Apple Silicon), got {machine}")
    LOGGER.info("diag platform ok macOS=%s arch=%s", platform.mac_ver()[0], machine, extra={"category": "CONFIG"})
    return CheckResult(True, "Platform", f"macOS {platform.mac_ver()[0]} on {machine}")


def check_dumpcap_present() -> CheckResult:
    path = shutil.which("dumpcap")
    if not path:
        LOGGER.error("diag dumpcap missing in PATH", extra={"category": "ERRORS"})
        return CheckResult(False, "dumpcap", "dumpcap not found in PATH. Install: brew install wireshark")
    rc, out, err = _run(["dumpcap", "--version"], timeout=5)
    if rc != 0:
        LOGGER.error("diag dumpcap --version failed err=%s", err.strip(), extra={"category": "ERRORS"})
        return CheckResult(False, "dumpcap", f"dumpcap --version failed: {err.strip()}")
    first_line = out.splitlines()[0] if out else "dumpcap detected"
    return CheckResult(True, "dumpcap", f"{path} ({first_line})")


def check_dumpcap_permissions() -> CheckResult:
    # This is a pragmatic check: if dumpcap can't enumerate any interfaces, it often indicates permissions.
    rc, out, err = _run(["dumpcap", "-D"], timeout=8)
    if rc != 0:
        msg = err.strip() or out.strip() or "dumpcap -D failed"
        return CheckResult(False, "dumpcap permissions", msg)
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        return CheckResult(False, "dumpcap permissions", "dumpcap -D returned no interfaces")
    return CheckResult(True, "dumpcap permissions", f"Interfaces listed: {len(lines)}")


def tcp_connect(host: str, port: int) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS):
            LOGGER.debug("diag tcp connect ok host=%s port=%s", host, port, extra={"category": "CAPTURE"})
            return None
    except Exception as exc:
        LOGGER.warning("diag tcp connect failed host=%s port=%s err=%s", host, port, exc, extra={"category": "CAPTURE"})
        return str(exc)


def dumpcap_preflight(rpcap_if: str) -> Optional[str]:
    # Validate that we can open the rpcap device and run a short capture.
    # This is the closest approximation to the real capture path.
    with tempfile.NamedTemporaryFile(prefix="rtphelper_rpcap_diag_", suffix=".pcap", delete=True) as tmp:
        cmd = [
            "dumpcap",
            "-F",
            "pcap",
            "-i",
            rpcap_if,
            "-w",
            tmp.name,
            "-a",
            f"duration:{PREFLIGHT_CAPTURE_SECONDS}",
        ]
        try:
            rc, out, err = _run(cmd, timeout=DUMPCAP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return f"timeout after {DUMPCAP_TIMEOUT_SECONDS}s"
        if rc != 0:
            msg = (err or out).strip()
            # Keep last line to reduce noise, but still useful.
            if msg:
                msg = msg.splitlines()[-1]
            return msg or f"exit code {rc}"
    return None


def load_hosts(config_path: Path) -> Dict[str, Any]:
    LOGGER.info("diag loading config path=%s", config_path, extra={"category": "CONFIG"})
    parsed = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("config root must be a mapping")
    return parsed


def iter_targets(config: Dict[str, Any], region: Optional[str]) -> List[Tuple[str, str, str, int]]:
    rpcap = config.get("rpcap") or {}
    port = rpcap.get("default_port") or DEFAULT_PORT

    regions = config.get("regions") or {}
    if region:
        if region not in regions:
            raise ValueError(f"region not found in config: {region}")
        regions = {region: regions[region]}

    targets: List[Tuple[str, str, str, int]] = []
    for region_name, region_obj in regions.items():
        hosts = (region_obj or {}).get("hosts") or []
        for host in hosts:
            host_id = str(host.get("id"))
            address = str(host.get("address"))
            host_port = int(host.get("port") or port)
            ifaces = host.get("interfaces") or []
            for iface in ifaces:
                targets.append((region_name, host_id, address + "/" + str(iface), host_port))
    return targets


def print_result(result: CheckResult) -> None:
    status = "PASS" if result.ok else "FAIL"
    line = f"[{status}] {result.title}"
    if result.details:
        line += f": {result.details}"
    print(line)


def main() -> int:
    setup_logging()
    run_cid = short_uuid()
    with correlation_context(run_cid):
        LOGGER.info("diag start", extra={"category": "CONFIG"})
        parser = argparse.ArgumentParser(description="Diagnose local rpcap compatibility and connectivity")
        parser.add_argument("--config", default="config/hosts.yaml", help="Path to hosts.yaml")
        parser.add_argument("--region", default=None, help="Limit checks to a single region")
        parser.add_argument("--skip-capture", action="store_true", help="Skip dumpcap preflight captures")
        args = parser.parse_args()

        config_path = Path(args.config)
        if not config_path.exists():
            print_result(CheckResult(False, "Config", f"File not found: {config_path}"))
            LOGGER.error("diag config missing path=%s", config_path, extra={"category": "ERRORS"})
            return 2

        results: List[CheckResult] = []
        results.append(check_macos_arm64())
        results.append(check_dumpcap_present())

        # Only check permissions if dumpcap exists.
        if results[-1].ok:
            results.append(check_dumpcap_permissions())

        for r in results:
            print_result(r)

        if any(not r.ok for r in results):
            print("\nStopping early due to local environment failures.")
            LOGGER.warning("diag stop early local checks failed", extra={"category": "ERRORS"})
            return 2

        try:
            cfg = load_hosts(config_path)
            targets = iter_targets(cfg, args.region)
        except Exception as exc:
            print_result(CheckResult(False, "Config", str(exc)))
            LOGGER.exception("diag config parse failed", extra={"category": "ERRORS"})
            return 2

        if not targets:
            print_result(CheckResult(False, "Targets", "No hosts/interfaces found in config"))
            LOGGER.error("diag no targets found", extra={"category": "ERRORS"})
            return 2

        LOGGER.info("diag targets loaded count=%s region=%s", len(targets), args.region or "all", extra={"category": "CONFIG"})
        print(f"\nChecking rpcap connectivity for {len(targets)} host/interface targets...")

        failed = False
        for region_name, host_id, addr_iface, port in targets:
            address, iface = addr_iface.split("/", 1)
            title = f"{region_name} {host_id} {address}:{port} iface={iface}"
            LOGGER.info("diag checking target=%s", title, extra={"category": "CAPTURE"})

            conn_err = tcp_connect(address, port)
            if conn_err:
                print_result(CheckResult(False, title, f"TCP connect failed: {conn_err}"))
                failed = True
                continue

            if args.skip_capture:
                print_result(CheckResult(True, title, "TCP connect OK (capture skipped)"))
                continue

            rpcap_if = f"rpcap://{address}:{port}/{iface}"
            cap_err = dumpcap_preflight(rpcap_if)
            if cap_err:
                print_result(CheckResult(False, title, f"dumpcap preflight failed: {cap_err}"))
                LOGGER.warning("diag preflight failed target=%s err=%s", title, cap_err, extra={"category": "CAPTURE"})
                failed = True
            else:
                print_result(CheckResult(True, title, "dumpcap preflight OK"))
                LOGGER.info("diag preflight ok target=%s", title, extra={"category": "CAPTURE"})

        if failed:
            print("\nOne or more checks failed.")
            LOGGER.warning("diag completed with failures", extra={"category": "ERRORS"})
            return 1

        print("\nAll checks passed.")
        LOGGER.info("diag completed successfully", extra={"category": "CONFIG"})
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
