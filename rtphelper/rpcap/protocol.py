from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Tuple

# RPCAP protocol constants (as in libpcap's pcap-rpcap.h)
RPCAP_VERSION = 0

RPCAP_MSG_ERROR = 1
RPCAP_MSG_FINDALLIF_REQ = 2
RPCAP_MSG_OPEN_REQ = 3
RPCAP_MSG_STARTCAP_REQ = 4
RPCAP_MSG_UPDATEFILTER_REQ = 5
RPCAP_MSG_CLOSE = 6
RPCAP_MSG_PACKET = 7
RPCAP_MSG_AUTH_REQ = 8
RPCAP_MSG_STATS_REQ = 9
RPCAP_MSG_ENDCAP_REQ = 10

RPCAP_MSG_FINDALLIF_REPLY = 2 + 128
RPCAP_MSG_OPEN_REPLY = 3 + 128
RPCAP_MSG_STARTCAP_REPLY = 4 + 128
RPCAP_MSG_UPDATEFILTER_REPLY = 5 + 128
RPCAP_MSG_AUTH_REPLY = 8 + 128
RPCAP_MSG_STATS_REPLY = 9 + 128
RPCAP_MSG_ENDCAP_REPLY = 10 + 128

RPCAP_ERR_AUTH_FAILED = 4

RPCAP_AUTH_NULL = 0

RPCAP_UPDATEFILTER_BPF = 1

# startcap flags
RPCAP_STARTCAPREQ_FLAG_PROMISC = 1

# Common DLT values (pcap LINKTYPE / DLT)
DLT_EN10MB = 1
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RpcapHeader:
    ver: int
    msg_type: int
    value: int
    plen: int


_HDR_STRUCT = struct.Struct("!BBHI")


def pack_header(msg_type: int, value: int, payload_len: int) -> bytes:
    return _HDR_STRUCT.pack(RPCAP_VERSION, msg_type, value & 0xFFFF, payload_len & 0xFFFFFFFF)


def unpack_header(data: bytes) -> RpcapHeader:
    ver, msg_type, value, plen = _HDR_STRUCT.unpack(data)
    return RpcapHeader(ver=ver, msg_type=msg_type, value=value, plen=plen)


def pack_auth_null() -> bytes:
    # struct rpcap_auth:
    # uint16 type; uint16 dummy; uint16 slen1; uint16 slen2;
    return struct.pack("!HHHH", RPCAP_AUTH_NULL, 0, 0, 0)


def pack_open_req(device: str) -> bytes:
    # libpcap sends the device string as raw bytes (no NUL), plen=len(device)
    return device.encode("utf-8", errors="strict")


def pack_startcap_req_v1(snaplen: int, read_timeout_ms: int, flags: int = 0, portdata: int = 0) -> bytes:
    # Older implementations:
    # uint32 snaplen; uint32 read_timeout; uint16 flags; uint16 portdata;
    return struct.pack("!IIHH", int(snaplen), int(read_timeout_ms), flags & 0xFFFF, portdata & 0xFFFF)


def pack_startcap_req_v2(
    snaplen: int,
    read_timeout_ms: int,
    flags: int = 0,
    portdata: int = 0,
    samp_method: int = 0,
    samp_value: int = 0,
) -> bytes:
    # Newer implementations:
    # uint32 snaplen; uint32 read_timeout; uint16 flags; rpcap_sampling samp; uint16 portdata; uint16 dummy;
    # Some servers use sizeof(struct rpcap_startcapreq) (with padding); we include an extra pad uint16.
    return struct.pack(
        "!IIHBBHHHH",
        int(snaplen),
        int(read_timeout_ms),
        flags & 0xFFFF,
        samp_method & 0xFF,
        samp_value & 0xFF,
        0,  # samp.dummy
        portdata & 0xFFFF,
        0,  # dummy
        0,  # pad
    )


def unpack_open_reply(payload: bytes) -> Tuple[int, int]:
    # struct rpcap_openreply: uint32 linktype; uint32 tzoff;
    if len(payload) < 8:
        LOGGER.error("RPCAP open reply too short payload_len=%s", len(payload), extra={"category": "ERRORS"})
        raise ValueError("open reply too short")
    linktype, tzoff = struct.unpack("!II", payload[:8])
    return int(linktype), int(tzoff)


def unpack_startcap_reply(payload: bytes) -> Tuple[int, int]:
    # struct rpcap_startcapreply: uint32 bufsize; uint16 portdata; uint16 dummy;
    if len(payload) < 8:
        LOGGER.error("RPCAP startcap reply too short payload_len=%s", len(payload), extra={"category": "ERRORS"})
        raise ValueError("startcap reply too short")
    bufsize, portdata, _dummy = struct.unpack("!IHH", payload[:8])
    return int(bufsize), int(portdata)


def unpack_packet_header(payload: bytes) -> Tuple[int, int, int, bytes]:
    # struct rpcap_pkthdr:
    # uint32 ts_sec; uint32 ts_usec; uint32 caplen; uint32 len;
    if len(payload) < 16:
        LOGGER.error("RPCAP packet payload too short payload_len=%s", len(payload), extra={"category": "ERRORS"})
        raise ValueError("packet payload too short")
    ts_sec, ts_usec, caplen, pktlen = struct.unpack("!IIII", payload[:16])

    # Observed in the wild: some rpcapd implementations prepend a 4-byte interface id
    # before the link-layer frame, while keeping caplen referring to the frame size only.
    remaining = payload[16:]
    if len(remaining) == caplen:
        frame = remaining[:caplen]
    elif len(remaining) == caplen + 4:
        frame = remaining[4:4 + caplen]
    else:
        # Fallback: take at least caplen bytes, but avoid crashing on unexpected layouts.
        frame = remaining[:caplen]
        if len(frame) != caplen:
            LOGGER.error(
                "RPCAP truncated packet data expected_caplen=%s available=%s",
                caplen,
                len(remaining),
                extra={"category": "ERRORS"},
            )
            raise ValueError("truncated packet data")
    return int(ts_sec), int(ts_usec), int(pktlen), frame


def pack_bpf_program(filter_type: int, insns: bytes) -> bytes:
    # struct rpcap_filter:
    # uint16 filtertype; uint16 dummy; uint32 nitems; then items
    # For BPF: items are 'struct bpf_insn' in network byte order? libpcap sends raw bpf_insn with host order fields converted.
    # We'll send items as packed big-endian fields: code(2) jt(1) jf(1) k(4)
    if len(insns) % 8 != 0:
        raise ValueError("bpf instructions must be a multiple of 8 bytes")
    nitems = len(insns) // 8
    return struct.pack("!HHI", filter_type & 0xFFFF, 0, nitems) + insns
