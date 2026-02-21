from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import PcapReader

from rtphelper.logging_setup import short_uuid
from rtphelper.services.sip_parser import SipCall

LOGGER = logging.getLogger(__name__)


@dataclass
class StreamMatch:
    host_id: str
    source_pcaps: List[Path]
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ssrc: int
    packet_count: int

    @property
    def stream_id(self) -> str:
        return f"{self.host_id}_{self.src_ip}_{self.src_port}_{self.dst_ip}_{self.dst_port}_{self.ssrc}"


def match_streams(
    call: SipCall,
    host_files: Dict[str, List[Path]],
    media_endpoints: Set[Tuple[str, int]] | None = None,
) -> List[StreamMatch]:
    """
    Match RTP/SRTP streams in captured pcaps against SIP-negotiated media.

    If `media_endpoints` is provided, matching is done by exact (ip,port) tuple in either direction:
      - (src_ip, src_port) in endpoints OR (dst_ip, dst_port) in endpoints
    This is more reliable when the SIP pcap describes multiple legs/hops and you want to scope matching.
    """
    endpoint_tuples: Set[Tuple[str, int]] = set(media_endpoints or set())

    negotiated_ports: Set[int] = set()
    negotiated_ips: Set[str] = set()
    negotiated_ssrcs: Set[int] = set()

    for media in call.media_sections:
        if media.port:
            negotiated_ports.add(media.port)
        if media.connection_ip:
            negotiated_ips.add(media.connection_ip)
        negotiated_ssrcs.update(media.ssrcs)

    grouped_counts: Dict[Tuple[str, str, int, str, int, int], int] = {}
    grouped_files: Dict[Tuple[str, str, int, str, int, int], Set[Path]] = {}

    for host_id, files in host_files.items():
        for pcap_file in files:
            if not pcap_file.exists():
                continue

            with PcapReader(str(pcap_file)) as reader:
                for packet in reader:
                    if IP not in packet or UDP not in packet:
                        continue
                    if Raw not in packet[UDP]:
                        continue

                    payload = bytes(packet[UDP][Raw].load)
                    if len(payload) < 12:
                        continue
                    if payload[0] >> 6 != 2:
                        continue

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = int(packet[UDP].sport)
                    dst_port = int(packet[UDP].dport)
                    ssrc = int.from_bytes(payload[8:12], byteorder="big")

                    if endpoint_tuples:
                        if (src_ip, src_port) not in endpoint_tuples and (dst_ip, dst_port) not in endpoint_tuples:
                            continue
                    else:
                        if not _is_candidate(
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            ssrc,
                            negotiated_ips,
                            negotiated_ports,
                            negotiated_ssrcs,
                        ):
                            continue

                    key = (host_id, src_ip, src_port, dst_ip, dst_port, ssrc)
                    grouped_counts[key] = grouped_counts.get(key, 0) + 1
                    grouped_files.setdefault(key, set()).add(pcap_file)

    matches = [
        StreamMatch(
            host_id=host_id,
            source_pcaps=sorted(grouped_files.get((host_id, src_ip, src_port, dst_ip, dst_port, ssrc), set())),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            ssrc=ssrc,
            packet_count=count,
        )
        for (host_id, src_ip, src_port, dst_ip, dst_port, ssrc), count in grouped_counts.items()
    ]

    LOGGER.info(
        "Matched streams call_id=%s count=%d",
        call.call_id,
        len(matches),
        extra={"category": "RTP_SEARCH", "correlation_id": call.call_id or short_uuid()},
    )
    return sorted(matches, key=lambda item: item.packet_count, reverse=True)


def _is_candidate(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    ssrc: int,
    negotiated_ips: Set[str],
    negotiated_ports: Set[int],
    negotiated_ssrcs: Set[int],
) -> bool:
    port_match = src_port in negotiated_ports or dst_port in negotiated_ports
    ip_match = not negotiated_ips or src_ip in negotiated_ips or dst_ip in negotiated_ips
    ssrc_match = not negotiated_ssrcs or ssrc in negotiated_ssrcs
    return (port_match and ip_match) or ssrc_match


def search_streams_by_src_host_port(
    host_files: Dict[str, List[Path]],
    from_host: str,
    from_port: int,
    *,
    leg_key: str = "unknown_leg",
    step_origin: str = "unknown",
    correlation_id: str | None = None,
) -> tuple[List[StreamMatch], Dict[Path, int]]:
    """
    Strict search: select RTP packets where src_ip == from_host AND src_port == from_port.

    Returns (matches, per_file_packet_counts).
    """
    cid = correlation_id or short_uuid()
    build_t0 = time.perf_counter()
    grouped_counts: Dict[Tuple[str, str, int, str, int, int], int] = {}
    grouped_files: Dict[Tuple[str, str, int, str, int, int], Set[Path]] = {}
    per_file_counts: Dict[Path, int] = {}
    file_discovery_t0 = time.perf_counter()
    target_files = sorted(
        [str(p) for files in host_files.values() for p in files if p.exists()],
        key=lambda v: v,
    )
    file_discovery_ms = int((time.perf_counter() - file_discovery_t0) * 1000)
    filter_info = {
        "from_host": from_host,
        "from_port": int(from_port),
        "direction": leg_key,
        "origin": step_origin,
    }
    search_cmd = f"src_ip == {from_host} AND src_port == {int(from_port)} AND RTP(v=2,len>=12)"

    LOGGER.info(
        "RTP search prepared filter=%s query=%s target_files=%s",
        filter_info,
        search_cmd,
        target_files,
        extra={"category": "RTP_SEARCH", "correlation_id": cid},
    )
    LOGGER.debug(
        "RTP search details filter=%s query=%s target_files=%s files_found=%s build_filter_ms=%s file_discovery_ms=%s",
        filter_info,
        search_cmd,
        target_files,
        len(target_files),
        int((time.perf_counter() - build_t0) * 1000),
        file_discovery_ms,
        extra={"category": "RTP_SEARCH", "correlation_id": cid},
    )

    def get_ips(pkt) -> tuple[Optional[str], Optional[str]]:
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
        return None, None

    search_t0 = time.perf_counter()
    for host_id, files in host_files.items():
        for pcap_file in files:
            if not pcap_file.exists():
                continue

            file_count = 0
            with PcapReader(str(pcap_file)) as reader:
                for packet in reader:
                    if UDP not in packet:
                        continue
                    if Raw not in packet[UDP]:
                        continue

                    src_ip, dst_ip = get_ips(packet)
                    if not src_ip or not dst_ip:
                        continue

                    src_port = int(packet[UDP].sport)
                    if src_ip != from_host or src_port != int(from_port):
                        continue

                    payload = bytes(packet[UDP][Raw].load)
                    if len(payload) < 12:
                        continue
                    if payload[0] >> 6 != 2:
                        continue

                    dst_port = int(packet[UDP].dport)
                    ssrc = int.from_bytes(payload[8:12], byteorder="big")

                    key = (host_id, src_ip, src_port, dst_ip, dst_port, ssrc)
                    grouped_counts[key] = grouped_counts.get(key, 0) + 1
                    grouped_files.setdefault(key, set()).add(pcap_file)
                    file_count += 1

            per_file_counts[pcap_file] = file_count

    matches = [
        StreamMatch(
            host_id=host_id,
            source_pcaps=sorted(grouped_files.get((host_id, src_ip, src_port, dst_ip, dst_port, ssrc), set())),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            ssrc=ssrc,
            packet_count=count,
        )
        for (host_id, src_ip, src_port, dst_ip, dst_port, ssrc), count in grouped_counts.items()
    ]
    packets_total = sum(per_file_counts.values())
    search_ms = int((time.perf_counter() - search_t0) * 1000)
    LOGGER.info(
        "RTP search completed filter=%s matches=%s packets=%s files_checked=%s",
        filter_info,
        len(matches),
        packets_total,
        len(per_file_counts),
        extra={"category": "RTP_SEARCH", "correlation_id": cid},
    )
    LOGGER.debug(
        "RTP search timing filter=%s search_ms=%s per_file_counts=%s",
        filter_info,
        search_ms,
        {str(k): int(v) for k, v in sorted(per_file_counts.items(), key=lambda kv: kv[0].name)},
        extra={"category": "RTP_SEARCH", "correlation_id": cid},
    )
    return sorted(matches, key=lambda item: item.packet_count, reverse=True), per_file_counts


def search_streams_by_udp_port_and_dst_ip(
    host_files: Dict[str, List[Path]],
    udp_port: int,
    dst_ip: str,
    *,
    leg_key: str = "unknown_leg",
    step_origin: str = "unknown",
    correlation_id: str | None = None,
) -> tuple[List[StreamMatch], Dict[Path, int]]:
    """
    Filter equivalent to: udp.port == <udp_port> and dst.ip == <dst_ip>
    - udp.port means source OR destination port
    - dst.ip means packet IP destination must match dst_ip
    """
    cid = correlation_id or short_uuid()
    grouped_counts: Dict[Tuple[str, str, int, str, int, int], int] = {}
    grouped_files: Dict[Tuple[str, str, int, str, int, int], Set[Path]] = {}
    per_file_counts: Dict[Path, int] = {}

    filter_info = {
        "udp_port": int(udp_port),
        "dst_ip": dst_ip,
        "direction": leg_key,
        "origin": step_origin,
    }
    search_cmd = f"(udp.sport == {int(udp_port)} OR udp.dport == {int(udp_port)}) AND ip.dst == {dst_ip} AND RTP(v=2,len>=12)"
    target_files = sorted([str(p) for files in host_files.values() for p in files if p.exists()], key=lambda v: v)

    LOGGER.info(
        "RTP search prepared filter=%s query=%s target_files=%s",
        filter_info,
        search_cmd,
        target_files,
        extra={"category": "RTP_SEARCH", "correlation_id": cid},
    )

    def get_ips(pkt) -> tuple[Optional[str], Optional[str]]:
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
        return None, None

    for host_id, files in host_files.items():
        for pcap_file in files:
            if not pcap_file.exists():
                continue
            file_count = 0
            with PcapReader(str(pcap_file)) as reader:
                for packet in reader:
                    if UDP not in packet:
                        continue
                    if Raw not in packet[UDP]:
                        continue
                    src_ip, pkt_dst_ip = get_ips(packet)
                    if not src_ip or not pkt_dst_ip:
                        continue
                    if pkt_dst_ip != dst_ip:
                        continue
                    src_port = int(packet[UDP].sport)
                    dst_port = int(packet[UDP].dport)
                    if src_port != int(udp_port) and dst_port != int(udp_port):
                        continue
                    payload = bytes(packet[UDP][Raw].load)
                    if len(payload) < 12 or (payload[0] >> 6) != 2:
                        continue
                    ssrc = int.from_bytes(payload[8:12], byteorder="big")
                    key = (host_id, src_ip, src_port, pkt_dst_ip, dst_port, ssrc)
                    grouped_counts[key] = grouped_counts.get(key, 0) + 1
                    grouped_files.setdefault(key, set()).add(pcap_file)
                    file_count += 1
            per_file_counts[pcap_file] = file_count

    matches = [
        StreamMatch(
            host_id=host_id,
            source_pcaps=sorted(grouped_files.get((host_id, src_ip, src_port, dst_ip2, dst_port, ssrc), set())),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip2,
            dst_port=dst_port,
            ssrc=ssrc,
            packet_count=count,
        )
        for (host_id, src_ip, src_port, dst_ip2, dst_port, ssrc), count in grouped_counts.items()
    ]
    LOGGER.info(
        "RTP search completed filter=%s matches=%s packets=%s files_checked=%s",
        filter_info,
        len(matches),
        sum(per_file_counts.values()),
        len(per_file_counts),
        extra={"category": "RTP_SEARCH", "correlation_id": cid},
    )
    return sorted(matches, key=lambda item: item.packet_count, reverse=True), per_file_counts
