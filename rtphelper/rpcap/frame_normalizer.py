from __future__ import annotations

import logging
from typing import Optional

# DLT/LINKTYPE values
DLT_EN10MB = 1
LOGGER = logging.getLogger(__name__)


def normalize_link_layer_frame(linktype: int, frame: bytes) -> bytes:
    """Normalize rpcapd frame payloads so Wireshark decodes them correctly.

    Observed rpcapd implementations may prefix captured frames with a 4-byte interface id
    even when LINKTYPE is Ethernet. That breaks Wireshark decoding unless the prefix is removed.

    This function is conservative: it only strips the prefix when the bytes after the prefix
    look like an Ethernet frame.
    """

    if linktype != DLT_EN10MB:
        return frame

    if len(frame) < 14:
        return frame

    # Heuristic: check for known EtherTypes.
    def ethertype_at(offset: int) -> Optional[int]:
        if len(frame) < offset + 14:
            return None
        return (frame[offset + 12] << 8) | frame[offset + 13]

    # Some common EtherTypes
    valid = {0x0800, 0x86DD, 0x8100, 0x88A8, 0x8847, 0x8848}

    et0 = ethertype_at(0)
    if et0 in valid:
        return frame

    # Try stripping a 4-byte prefix (rpcap interface id / metadata)
    et4 = ethertype_at(4)
    if et4 in valid:
        LOGGER.debug("Stripping 4-byte rpcap prefix from Ethernet frame", extra={"category": "CAPTURE"})
        return frame[4:]

    return frame
