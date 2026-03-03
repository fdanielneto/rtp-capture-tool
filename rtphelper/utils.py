from __future__ import annotations

import logging
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REQUIRED_BINARIES = ["dumpcap"]
LOGGER = logging.getLogger(__name__)


def ensure_macos_arm() -> None:
    if platform.system() != "Darwin":
        LOGGER.error("Unsupported platform system=%s", platform.system(), extra={"category": "ERRORS"})
        sys.exit("This application is supported only on macOS.")
    if platform.machine() != "arm64":
        LOGGER.error("Unsupported architecture machine=%s", platform.machine(), extra={"category": "ERRORS"})
        sys.exit("This application requires Apple Silicon (arm64, M1 or newer).")


def ensure_binaries(required: list[str] | None = None) -> None:
    required = REQUIRED_BINARIES if required is None else required
    missing = [binary for binary in required if shutil.which(binary) is None]
    if missing:
        LOGGER.error("Missing required binaries=%s", missing, extra={"category": "ERRORS"})
        sys.exit(
            "Missing required binaries in PATH: "
            + ", ".join(missing)
            + ". Install Wireshark CLI tools with: brew install wireshark"
        )


def run_subprocess(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        LOGGER.error("Subprocess failed cmd=%s returncode=%s stderr=%s", cmd, proc.returncode, (proc.stderr or "")[:500], extra={"category": "ERRORS"})
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{proc.stderr}")
    return proc


def ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
