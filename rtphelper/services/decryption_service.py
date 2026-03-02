from __future__ import annotations

import logging
import shutil
import time
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from pylibsrtp import Policy, Session
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter

from rtphelper.logging_setup import correlation_context
from rtphelper.services.sip_parser import SipCall, SdesCryptoMaterial
from rtphelper.services.stream_matcher import StreamMatch

LOGGER = logging.getLogger(__name__)


@dataclass
class DecryptionResult:
    stream_id: str
    status: str
    message: str
    output_file: Optional[Path] = None


class DecryptionService:
    @staticmethod
    def _inline_from_material(material: SdesCryptoMaterial) -> str:
        raw = material.master_key + material.master_salt
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def _map_suite_to_srtp_profile(suite: str) -> int:
        """
        Map SDES crypto suite name to pylibsrtp profile constant.
        Returns the appropriate SRTP_PROFILE_* value for Policy.
        """
        normalized = (suite or "").strip().upper().replace("-", "_")
        if "AEAD_AES_256_GCM" in normalized:
            return Policy.SRTP_PROFILE_AEAD_AES_256_GCM
        if "AEAD_AES_128_GCM" in normalized:
            return Policy.SRTP_PROFILE_AEAD_AES_128_GCM
        if "AES_CM_128_HMAC_SHA1_32" in normalized or "AES128_CM_SHA1_32" in normalized:
            return Policy.SRTP_PROFILE_AES128_CM_SHA1_32
        # Default to AES128_CM_SHA1_80 for AES_CM_128_HMAC_SHA1_80 and unknown suites
        return Policy.SRTP_PROFILE_AES128_CM_SHA1_80

    def decrypt_streams(
        self,
        mode: str,
        call: SipCall,
        streams: List[StreamMatch],
        output_dir: Path,
    ) -> List[DecryptionResult]:
        cid = call.call_id or "-"
        start_ts = time.perf_counter()
        output_dir.mkdir(parents=True, exist_ok=True)
        with correlation_context(cid):
            LOGGER.info(
                "Starting decrypt streams mode=%s streams=%s output_dir=%s",
                mode,
                len(streams),
                output_dir,
                extra={"category": "SRTP_DECRYPT", "correlation_id": cid},
            )

            selected_mode = self._select_mode(mode, call)
            LOGGER.info("Decrypt selected mode=%s requested_mode=%s", selected_mode, mode, extra={"category": "SRTP_DECRYPT", "correlation_id": cid})
            if selected_mode == "dtls":
                material = self._resolve_dtls_key(call)
                if material is None:
                    message = (
                        "DTLS-SRTP was detected but decryption could not be completed. "
                        "SIP fingerprint data alone does not provide SRTP session keys. "
                        "Provide SDP with exported keying material (a=dtls-srtp-key) or use SDES-SRTP."
                    )
                    return [
                        DecryptionResult(
                            stream_id=stream.stream_id,
                            status="unsupported",
                            message=message,
                        )
                        for stream in streams
                    ]
                crypto = material
            else:
                crypto = self._resolve_sdes_key(call)
                if crypto is None:
                    LOGGER.warning("No SDES key material found for call", extra={"category": "SDES_KEYS", "correlation_id": cid})
                    return [
                        DecryptionResult(
                            stream_id=stream.stream_id,
                            status="failed",
                            message="No SDES key material found in SIP pcap",
                        )
                        for stream in streams
                    ]
                LOGGER.info(
                    "Decrypt stream mode selected suite=%s inline=%s",
                    crypto.suite,
                    self._inline_from_material(crypto),
                    extra={"category": "SDES_KEYS", "correlation_id": cid},
                )

            results: List[DecryptionResult] = []
            for stream in streams:
                output_file = output_dir / f"{stream.stream_id}_decrypted.pcap"
                try:
                    LOGGER.debug(
                        "Decrypting stream stream_id=%s src=%s:%s dst=%s:%s ssrc=%s source_pcaps=%s",
                        stream.stream_id,
                        stream.src_ip,
                        stream.src_port,
                        stream.dst_ip,
                        stream.dst_port,
                        stream.ssrc,
                        [str(p) for p in stream.source_pcaps],
                        extra={"category": "SRTP_DECRYPT", "correlation_id": cid},
                    )
                    decrypted_packets = self._decrypt_single_stream(stream, crypto, output_file)
                    if decrypted_packets == 0:
                        results.append(
                            DecryptionResult(
                                stream_id=stream.stream_id,
                                status="failed",
                                message="No packets could be decrypted for this stream",
                            )
                        )
                    else:
                        results.append(
                            DecryptionResult(
                                stream_id=stream.stream_id,
                                status="success",
                                message=f"Decrypted packets: {decrypted_packets}",
                                output_file=output_file,
                            )
                        )
                except Exception as exc:
                    LOGGER.exception("Failed decrypting stream=%s", stream.stream_id, extra={"category": "ERRORS", "correlation_id": cid})
                    results.append(
                        DecryptionResult(
                            stream_id=stream.stream_id,
                            status="failed",
                            message=f"Decryption error: {exc}",
                        )
                    )

            elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
            status_counts: dict[str, int] = {}
            for item in results:
                status_counts[item.status] = status_counts.get(item.status, 0) + 1
            LOGGER.info(
                "Decrypt streams completed status_counts=%s duration_ms=%s",
                status_counts,
                elapsed_ms,
                extra={"category": "SRTP_DECRYPT", "correlation_id": cid},
            )
            return results

    def _select_mode(self, requested_mode: str, call: SipCall) -> str:
        if requested_mode in {"sdes", "dtls"}:
            return requested_mode

        has_sdes = any(section.sdes_cryptos for section in call.media_sections)
        return "sdes" if has_sdes else "dtls"

    def _resolve_sdes_key(self, call: SipCall) -> Optional[SdesCryptoMaterial]:
        for section in call.media_sections:
            if section.sdes_cryptos:
                return section.sdes_cryptos[0]
        return None

    def _resolve_dtls_key(self, call: SipCall) -> Optional[SdesCryptoMaterial]:
        for section in call.media_sections:
            if section.dtls_exporter_key and len(section.dtls_exporter_key) >= 30:
                raw = section.dtls_exporter_key
                return SdesCryptoMaterial(
                    suite="AES_CM_128_HMAC_SHA1_80",
                    master_key=raw[:16],
                    master_salt=raw[16:30],
                )
        return None

    def _decrypt_single_stream(self, stream: StreamMatch, crypto: SdesCryptoMaterial, output_file: Path) -> int:
        key_blob = crypto.master_key + crypto.master_salt
        srtp_profile = self._map_suite_to_srtp_profile(crypto.suite)
        policy = Policy(key=key_blob, ssrc_type=Policy.SSRC_ANY_INBOUND, srtp_profile=srtp_profile)
        session = Session(policy)

        decrypted_count = 0
        writer = PcapWriter(str(output_file), append=False, sync=True)

        for source_pcap in stream.source_pcaps:
            with PcapReader(str(source_pcap)) as reader:
                for packet in reader:
                    if IP not in packet or UDP not in packet or Raw not in packet[UDP]:
                        continue

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = int(packet[UDP].sport)
                    dst_port = int(packet[UDP].dport)
                    if (
                        src_ip != stream.src_ip
                        or dst_ip != stream.dst_ip
                        or src_port != stream.src_port
                        or dst_port != stream.dst_port
                    ):
                        continue

                    payload = bytes(packet[UDP][Raw].load)
                    if len(payload) < 12:
                        continue

                    # SSRC match (helps avoid mixing multiple calls on same ports)
                    ssrc = int.from_bytes(payload[8:12], byteorder="big")
                    if ssrc != stream.ssrc:
                        continue

                    try:
                        decrypted_payload = session.unprotect(payload)
                    except Exception:
                        LOGGER.debug(
                            "Packet decrypt failed stream_id=%s source_pcap=%s",
                            stream.stream_id,
                            source_pcap,
                            extra={"category": "SRTP_DECRYPT"},
                        )
                        continue

                    packet[UDP].remove_payload()
                    packet[UDP].add_payload(Raw(load=decrypted_payload))
                    if hasattr(packet[IP], "len"):
                        del packet[IP].len
                    if hasattr(packet[IP], "chksum"):
                        del packet[IP].chksum
                    if hasattr(packet[UDP], "len"):
                        del packet[UDP].len
                    if hasattr(packet[UDP], "chksum"):
                        del packet[UDP].chksum
                    writer.write(packet)
                    decrypted_count += 1

        writer.close()

        if decrypted_count == 0 and output_file.exists():
            output_file.unlink()

        return decrypted_count

    def decrypt_or_copy_pcap(
        self,
        call: SipCall,
        input_pcap: Path,
        output_dir: Path,
        output_prefix: str,
        crypto_materials: List[SdesCryptoMaterial] | None = None,
        encrypted_expected: bool = False,
    ) -> DecryptionResult:
        """
        Decrypt a filtered pcap file packet-by-packet.
        - If packets decrypt, writes <prefix>-decrypted.pcap
        - If no packet decrypts, copies input to <prefix>-no-decrypt-need.pcap
        """
        cid = call.call_id or "-"
        output_dir.mkdir(parents=True, exist_ok=True)
        materials = list(crypto_materials or [])
        if not materials:
            selected_mode = self._select_mode("auto", call)
            crypto = self._resolve_dtls_key(call) if selected_mode == "dtls" else self._resolve_sdes_key(call)
            if crypto is not None:
                materials = [crypto]
        if not materials:
            out = output_dir / f"{output_prefix}-no-decrypt-need.pcap"
            shutil.copy2(input_pcap, out)
            msg = (
                "Encrypted media expected but no decryption key material available; copied as no-decrypt-need"
                if encrypted_expected
                else "No decryption required (media not expected to be encrypted); copied as no-decrypt-need"
            )
            return DecryptionResult(
                stream_id=output_prefix,
                status="copied",
                message=msg,
                output_file=out,
            )

        for idx, material in enumerate(materials):
            LOGGER.info(
                "Decrypt input material stream_id=%s material_index=%s suite=%s inline=%s",
                output_prefix,
                idx + 1,
                material.suite,
                self._inline_from_material(material),
                extra={"category": "SDES_KEYS", "correlation_id": cid},
            )

        sessions: List[Session] = []
        for mat in materials:
            key_blob = mat.master_key + mat.master_salt
            srtp_profile = self._map_suite_to_srtp_profile(mat.suite)
            policy = Policy(key=key_blob, ssrc_type=Policy.SSRC_ANY_INBOUND, srtp_profile=srtp_profile)
            sessions.append(Session(policy))
            LOGGER.debug(
                "Created SRTP session suite=%s srtp_profile=%s stream_id=%s",
                mat.suite,
                srtp_profile,
                output_prefix,
                extra={"category": "SDES_KEYS", "correlation_id": cid},
            )

        tmp_out = output_dir / f"{output_prefix}-decrypted.pcap"
        writer = PcapWriter(str(tmp_out), append=False, sync=True)
        total_packets = 0
        total_rtp = 0
        decrypted_count = 0
        try:
            with PcapReader(str(input_pcap)) as reader:
                for packet in reader:
                    total_packets += 1
                    if IP in packet and UDP in packet and Raw in packet[UDP]:
                        payload = bytes(packet[UDP][Raw].load)
                        if len(payload) >= 12 and (payload[0] >> 6) == 2:
                            total_rtp += 1
                            for sess in sessions:
                                try:
                                    decrypted_payload = sess.unprotect(payload)
                                    packet[UDP].remove_payload()
                                    packet[UDP].add_payload(Raw(load=decrypted_payload))
                                    if hasattr(packet[IP], "len"):
                                        del packet[IP].len
                                    if hasattr(packet[IP], "chksum"):
                                        del packet[IP].chksum
                                    if hasattr(packet[UDP], "len"):
                                        del packet[UDP].len
                                    if hasattr(packet[UDP], "chksum"):
                                        del packet[UDP].chksum
                                    decrypted_count += 1
                                    break
                                except Exception:
                                    continue
                    writer.write(packet)
        finally:
            writer.close()

        if decrypted_count > 0:
            return DecryptionResult(
                stream_id=output_prefix,
                status="success",
                message=f"Decrypted RTP packets: {decrypted_count} (rtp_seen={total_rtp}, total_packets={total_packets})",
                output_file=tmp_out,
            )

        # No decryption happened: keep a no-decrypt-need file.
        if tmp_out.exists():
            tmp_out.unlink()
        out = output_dir / f"{output_prefix}-no-decrypt-need.pcap"
        shutil.copy2(input_pcap, out)
        return DecryptionResult(
            stream_id=output_prefix,
            status="copied",
            message=f"No decrypt needed or no decryptable packets (rtp_seen={total_rtp}, total_packets={total_packets})",
            output_file=out,
        )
