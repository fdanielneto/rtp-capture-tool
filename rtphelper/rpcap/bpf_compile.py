from __future__ import annotations

import ctypes
import ctypes.util
import logging
import struct
from dataclasses import dataclass
from typing import List

LOGGER = logging.getLogger(__name__)

class _BpfInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [
        ("bf_len", ctypes.c_uint),
        ("bf_insns", ctypes.POINTER(_BpfInsn)),
    ]


class _PcapT(ctypes.Structure):
    pass


def compile_bpf(filter_expr: str, linktype: int, snaplen: int, optimize: bool = True, netmask: int = 0xFFFFFFFF) -> bytes:
    if not filter_expr:
        LOGGER.debug("BPF compile skipped (empty filter)", extra={"category": "RTP_SEARCH"})
        return b""
    LOGGER.debug(
        "Compiling BPF filter_expr=%s linktype=%s snaplen=%s optimize=%s netmask=%s",
        filter_expr,
        linktype,
        snaplen,
        optimize,
        netmask,
        extra={"category": "RTP_SEARCH"},
    )

    libname = ctypes.util.find_library("pcap")
    if not libname:
        LOGGER.error("libpcap not found for BPF compile", extra={"category": "ERRORS"})
        raise RuntimeError("libpcap not found")

    libpcap = ctypes.CDLL(libname)

    libpcap.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
    libpcap.pcap_open_dead.restype = ctypes.POINTER(_PcapT)

    libpcap.pcap_compile.argtypes = [ctypes.POINTER(_PcapT), ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    libpcap.pcap_compile.restype = ctypes.c_int

    libpcap.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
    libpcap.pcap_freecode.restype = None

    pcap = libpcap.pcap_open_dead(int(linktype), int(snaplen))
    if not pcap:
        LOGGER.error("pcap_open_dead failed linktype=%s snaplen=%s", linktype, snaplen, extra={"category": "ERRORS"})
        raise RuntimeError("pcap_open_dead failed")

    program = _BpfProgram()
    rc = libpcap.pcap_compile(
        pcap,
        ctypes.byref(program),
        filter_expr.encode("utf-8"),
        1 if optimize else 0,
        ctypes.c_uint32(netmask),
    )
    if rc != 0:
        # pcap_geterr would require pcap_t; keep generic.
        LOGGER.error("BPF compile failed filter_expr=%s", filter_expr, extra={"category": "ERRORS"})
        raise ValueError("BPF compile failed for filter expression")

    try:
        n = int(program.bf_len)
        if n <= 0:
            return b""
        insns = []
        for i in range(n):
            insn = program.bf_insns[i]
            # Network byte order: code(2), jt(1), jf(1), k(4)
            insns.append(struct.pack("!HBBI", int(insn.code), int(insn.jt), int(insn.jf), int(insn.k)))
        LOGGER.debug("BPF compile succeeded instructions=%s", n, extra={"category": "RTP_SEARCH"})
        return b"".join(insns)
    finally:
        libpcap.pcap_freecode(ctypes.byref(program))
