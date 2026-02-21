from pathlib import Path
import click
from .utils import ensure_macos_arm, ensure_binaries
from .capture import start_capture
from .decrypt import decrypt_workflow

@click.group()
def main():
    """rtphelper - captura e desencriptação SDES-SRTP (macOS ARM)."""
    ensure_macos_arm()
    ensure_binaries()

@main.command()
@click.option("--media-host", prompt="Media host (rpcapd)", help="Host/IP onde corre rpcapd.")
@click.option("--iface", prompt="Interface remota (ex: 1, en0)", help="ID ou nome da interface remota.")
@click.option("--filter", "bpf_filter", prompt="Filtro de captura BPF", help="Ex: udp and host 10.11.10.42")
@click.option("--duration", type=int, default=60, show_default=True, help="Duração em segundos.")
@click.option("--out-dir", type=click.Path(path_type=Path), default=Path("captures"), show_default=True)
def capture(media_host, iface, bpf_filter, duration, out_dir):
    """Captura media via rpcapd e grava PCAP encriptado."""
    start_capture(media_host, iface, bpf_filter, duration, out_dir)

@main.command()
@click.option("--sip-pcap", type=click.Path(exists=True, path_type=Path), prompt="PCAP com SIP+SDP")
@click.option("--media-pcap", type=click.Path(exists=True, path_type=Path), prompt="PCAP de media (SRTP)")
@click.option("--call-id", default=None, help="Opcional: filtrar por Call-ID.")
@click.option("--out-dir", type=click.Path(path_type=Path), default=Path("output"), show_default=True)
def decrypt(sip_pcap, media_pcap, call_id, out_dir):
    """Desencripta SDES-SRTP e gera PCAP com RTP em claro."""
    decrypt_workflow(sip_pcap, media_pcap, call_id, out_dir)

@main.command()
def wizard():
    """Workflow interactivo end-to-end para 1ª linha."""
    media_host = click.prompt("Media host (rpcapd)")
    iface = click.prompt("Interface remota (ex: 1, en0)")
    bpf_filter = click.prompt("Filtro de captura BPF", default="udp")
    duration = click.prompt("Duração da captura (segundos)", default=60, type=int)

    capture_dir = Path("captures")
    media_pcap = start_capture(media_host, iface, bpf_filter, duration, capture_dir)

    sip_pcap = click.prompt("Caminho para PCAP com SIP+SDP", type=str)
    call_id = click.prompt("Call-ID (vazio para auto)", default="", show_default=False)
    call_id = call_id or None

    decrypt_workflow(Path(sip_pcap), media_pcap, call_id, Path("output"))
