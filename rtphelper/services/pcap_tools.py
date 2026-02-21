from __future__ import annotations

import logging
import heapq
from pathlib import Path
from typing import Iterable, List

from scapy.all import PcapReader, PcapWriter

LOGGER = logging.getLogger(__name__)


def merge_pcaps(output_pcap: Path, input_pcaps: List[Path]) -> Path:
    """Merge multiple pcap/pcapng files into a single pcap.

    Notes:
    - Packets are merged globally by timestamp (chronological order).
    - Packet timestamps are preserved via Scapy's packet.time.
    """
    output_pcap.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.info(
        "Merging pcaps output=%s inputs=%s",
        output_pcap,
        [str(p) for p in input_pcaps],
        extra={"category": "FILES"},
    )

    readers: List[PcapReader] = []
    heap: list[tuple[float, int, int, object]] = []
    seq = 0

    def pkt_time(pkt: object) -> float:
        t = getattr(pkt, "time", None)
        try:
            return float(t) if t is not None else 0.0
        except Exception:
            return 0.0

    # Open readers and prime heap with first packet from each.
    # Keep stable reader indexing independent of skipped/missing files.
    reader_index = 0
    for pcap in input_pcaps:
        if not pcap.exists():
            continue
        reader = PcapReader(str(pcap))
        readers.append(reader)
        try:
            pkt = next(iter(reader))
        except StopIteration:
            continue
        heapq.heappush(heap, (pkt_time(pkt), seq, reader_index, pkt))
        seq += 1
        reader_index += 1

    writer = PcapWriter(str(output_pcap), append=False, sync=True)
    try:
        # K-way merge by timestamp.
        while heap:
            _t, _seq, idx, pkt = heapq.heappop(heap)
            writer.write(pkt)

            reader = readers[idx]
            try:
                next_pkt = next(iter(reader))
            except StopIteration:
                continue
            heapq.heappush(heap, (pkt_time(next_pkt), seq, idx, next_pkt))
            seq += 1
    finally:
        writer.close()
        for reader in readers:
            try:
                reader.close()
            except Exception:
                pass

    LOGGER.info("Merge completed output=%s", output_pcap, extra={"category": "FILES"})
    return output_pcap
