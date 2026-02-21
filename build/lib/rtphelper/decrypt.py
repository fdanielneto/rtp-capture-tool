from pathlib import Path
from .sip_sdes import extract_sdes_keys_from_pcap
from .srtp_decode import decrypt_srtp_pcap, SrtpContext

def decrypt_workflow(sip_pcap: Path, media_pcap: Path, call_id: str | None, out_dir: Path) -> Path:
    keys = extract_sdes_keys_from_pcap(sip_pcap, call_id_filter=call_id)
    key = keys[0]  # para 1ª linha, usar a primeira chave encontrada

    ctx = SrtpContext(master_key=key.master_key, master_salt=key.master_salt)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{media_pcap.stem}_decrypted.pcapng"

    print("[INFO] A desencriptar SRTP com chave SDES extraída do SIP...")
    decrypt_srtp_pcap(media_pcap, out_file, ctx)
    print(f"[OK] PCAP gerado com RTP em claro: {out_file}")
    return out_file
