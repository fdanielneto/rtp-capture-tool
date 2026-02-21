import shutil
import subprocess
import sys
import platform
from pathlib import Path

REQUIRED_BINARIES = ["dumpcap", "text2pcap", "tshark"]

def ensure_macos_arm():
    if platform.system() != "Darwin":
        sys.exit("rtphelper só é suportado em macOS.")
    machine = platform.machine()
    if machine != "arm64":
        sys.exit("rtphelper requer macOS em arquitetura ARM (Apple Silicon, arm64).")

def ensure_binaries():
    missing = [b for b in REQUIRED_BINARIES if shutil.which(b) is None]
    if missing:
        msg = (
            "Os seguintes binários não foram encontrados no PATH: "
            f"{', '.join(missing)}.\n"
            "Instala Wireshark CLI no macOS, por exemplo: brew install wireshark."
        )
        sys.exit(msg)

def run_subprocess(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        sys.stderr.write(f"Erro ao correr: {' '.join(cmd)}\n")
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode)
    return proc

def ensure_dir(p: Path):
    p.parent.mkdir(parents=True, exist_ok=True)
