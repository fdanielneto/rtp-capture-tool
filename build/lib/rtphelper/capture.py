import datetime as dt
from pathlib import Path
from .utils import ensure_dir, run_subprocess

DEFAULT_RPCAP_PORT = 2002  # porto default RPCAP [web:59]

def build_rpcap_interface(host: str, iface: str, port: int = DEFAULT_RPCAP_PORT) -> str:
    # formato suportado por dumpcap: rpcap://host:port/iface [web:59][web:62]
    return f"rpcap://{host}:{port}/{iface}"

def start_capture(
    media_host: str,
    iface: str,
    bpf_filter: str,
    duration: int | None,
    out_dir: Path,
) -> Path:
    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"media_{ts}.pcapng"
    ensure_dir(out_file)
    rpcap_if = build_rpcap_interface(media_host, iface)

    cmd = ["dumpcap", "-i", rpcap_if, "-w", str(out_file)]
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    if duration:
        cmd += ["-a", f"duration:{duration}"]

    print(f"[INFO] A iniciar captura em {rpcap_if}...")
    proc = run_subprocess(cmd, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"Erro na captura: {proc.stderr}")
    print(f"[OK] Captura concluída: {out_file}")
    return out_file
