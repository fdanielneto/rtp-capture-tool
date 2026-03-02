from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from typing import Optional

from rtphelper.rpcap.bpf_compile import compile_bpf
from rtphelper.rpcap.protocol import (
    RPCAP_MSG_AUTH_REPLY,
    RPCAP_MSG_AUTH_REQ,
    RPCAP_MSG_CLOSE,
    RPCAP_MSG_ENDCAP_REPLY,
    RPCAP_MSG_ENDCAP_REQ,
    RPCAP_MSG_ERROR,
    RPCAP_MSG_OPEN_REPLY,
    RPCAP_MSG_OPEN_REQ,
    RPCAP_MSG_PACKET,
    RPCAP_MSG_STARTCAP_REPLY,
    RPCAP_MSG_STARTCAP_REQ,
    RPCAP_MSG_UPDATEFILTER_REPLY,
    RPCAP_MSG_UPDATEFILTER_REQ,
    RPCAP_UPDATEFILTER_BPF,
    RPCAP_STARTCAPREQ_FLAG_PROMISC,
    pack_auth_null,
    pack_bpf_program,
    pack_header,
    pack_open_req,
    pack_startcap_req_v1,
    pack_startcap_req_v2,
    unpack_header,
    unpack_open_reply,
    unpack_packet_header,
    unpack_startcap_reply,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class RpcapOpenInfo:
    linktype: int
    tzoff: int


class RpcapClient:
    def __init__(self, host: str, port: int = 2002, timeout: float = 10.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._data_sock: Optional[socket.socket] = None
        self._open_info: Optional[RpcapOpenInfo] = None

    def connect(self) -> None:
        if self._sock is not None:
            return
        LOGGER.debug("Connecting rpcap host=%s port=%s", self._host, self._port, extra={"category": "CAPTURE"})
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        sock.settimeout(self._timeout)
        self._sock = sock

    def close(self) -> None:
        if self._sock is None:
            return
        if self._data_sock is not None:
            try:
                self._data_sock.close()
            finally:
                self._data_sock = None
        try:
            self._send(RPCAP_MSG_CLOSE, 0, b"")
        except Exception:
            pass
        try:
            self._sock.close()
        finally:
            self._sock = None

    def auth_null(self) -> None:
        self._ensure_connected()
        LOGGER.debug("RPCAP auth null host=%s", self._host, extra={"category": "CAPTURE"})
        self._send(RPCAP_MSG_AUTH_REQ, 0, pack_auth_null())
        msg_type, value, payload = self._recv_msg()
        if msg_type == RPCAP_MSG_ERROR:
            raise RuntimeError(self._format_error("RPCAP auth failed", value, payload))
        if msg_type != RPCAP_MSG_AUTH_REPLY:
            raise RuntimeError(f"Unexpected RPCAP message during auth: {msg_type}")

    def open(self, device: str) -> RpcapOpenInfo:
        self._ensure_connected()
        LOGGER.debug("RPCAP open host=%s device=%s", self._host, device, extra={"category": "CAPTURE"})
        payload = pack_open_req(device)
        self._send(RPCAP_MSG_OPEN_REQ, 0, payload)
        msg_type, value, reply = self._recv_msg()
        if msg_type == RPCAP_MSG_ERROR:
            raise RuntimeError(self._format_error("RPCAP open failed", value, reply))
        if msg_type != RPCAP_MSG_OPEN_REPLY:
            raise RuntimeError(f"Unexpected RPCAP message during open: {msg_type}")
        linktype, tzoff = unpack_open_reply(reply)
        self._open_info = RpcapOpenInfo(linktype=linktype, tzoff=tzoff)
        return self._open_info

    def set_filter(self, filter_expr: str, snaplen: int = 262144) -> None:
        if not filter_expr:
            return
        if self._open_info is None:
            raise RuntimeError("RPCAP device must be opened before setting filter")

        LOGGER.debug("RPCAP set filter host=%s expr=%s snaplen=%s", self._host, filter_expr, snaplen, extra={"category": "CAPTURE"})
        insns = compile_bpf(filter_expr, linktype=self._open_info.linktype, snaplen=snaplen)
        payload = pack_bpf_program(RPCAP_UPDATEFILTER_BPF, insns)
        self._send(RPCAP_MSG_UPDATEFILTER_REQ, 0, payload)
        msg_type, value, reply = self._recv_msg()
        if msg_type == RPCAP_MSG_ERROR:
            raise RuntimeError(self._format_error("RPCAP set_filter failed", value, reply))
        if msg_type != RPCAP_MSG_UPDATEFILTER_REPLY:
            raise RuntimeError(f"Unexpected RPCAP message during set_filter: {msg_type}")

    def start_capture(
        self,
        snaplen: int = 262144,
        read_timeout_ms: int = 1000,
        promisc: bool = True,
        filter_expr: str | None = "",
    ) -> None:
        self._ensure_connected()
        LOGGER.debug(
            "RPCAP start capture host=%s snaplen=%s timeout_ms=%s promisc=%s filter=%s",
            self._host,
            snaplen,
            read_timeout_ms,
            promisc,
            filter_expr,
            extra={"category": "CAPTURE"},
        )
        flags = RPCAP_STARTCAPREQ_FLAG_PROMISC if promisc else 0
        if self._open_info is None:
            raise RuntimeError("RPCAP device must be opened before starting capture")

        # Some rpcapd implementations require the filter program to be included in STARTCAP.
        # In practice, an empty filter expression should mean "no filtering"; however, some servers
        # reject a zero-length/empty program. Use an accept-all filter that compiles to a valid BPF program.
        extra_filter = b""
        if filter_expr is not None:
            effective_expr = filter_expr.strip()
            if effective_expr == "":
                effective_expr = "len >= 0"  # accept all packets
            insns = compile_bpf(effective_expr, linktype=self._open_info.linktype, snaplen=snaplen)
            extra_filter = pack_bpf_program(RPCAP_UPDATEFILTER_BPF, insns)

        # There are at least two startcap request layouts in the wild. Try v2 first, then fallback to v1.
        last_error: Optional[str] = None
        for payload_to_try in (
            pack_startcap_req_v2(snaplen=snaplen, read_timeout_ms=read_timeout_ms, flags=flags) + extra_filter,
            pack_startcap_req_v1(snaplen=snaplen, read_timeout_ms=read_timeout_ms, flags=flags) + extra_filter,
        ):
            self._send(RPCAP_MSG_STARTCAP_REQ, 0, payload_to_try)
            msg_type, value, payload = self._recv_msg()
            if msg_type == RPCAP_MSG_STARTCAP_REPLY:
                bufsize, portdata = unpack_startcap_reply(payload)
                LOGGER.info(
                    "RPCAP server buffer size host=%s bufsize=%s bytes (%.2f MB)",
                    self._host,
                    bufsize,
                    bufsize / (1024 * 1024),
                    extra={"category": "CAPTURE"},
                )
                # In passive mode, rpcapd opens a separate TCP port for the data stream.
                if portdata:
                    data_sock = socket.create_connection((self._host, int(portdata)), timeout=self._timeout)
                    data_sock.settimeout(self._timeout)
                    self._data_sock = data_sock
                return
            if msg_type == RPCAP_MSG_ERROR:
                last_error = self._format_error("RPCAP start_capture failed", value, payload)
                # If the server complains about filter support / payload size, try the other layout.
                continue
            raise RuntimeError(f"Unexpected RPCAP message during start_capture: {msg_type}")

        raise RuntimeError(last_error or "RPCAP start_capture failed")

    def end_capture(self) -> None:
        if self._sock is None:
            return
        self._send(RPCAP_MSG_ENDCAP_REQ, 0, b"")
        msg_type, value, _payload = self._recv_msg()
        if msg_type == RPCAP_MSG_ERROR:
            raise RuntimeError(self._format_error("RPCAP end_capture failed", value, _payload))
        if msg_type != RPCAP_MSG_ENDCAP_REPLY:
            raise RuntimeError(f"Unexpected RPCAP message during end_capture: {msg_type}")
        if self._data_sock is not None:
            try:
                self._data_sock.close()
            finally:
                self._data_sock = None

    def recv_packet(self) -> tuple[int, int, int, bytes] | None:
        msg_type, value, payload = self._recv_msg(from_data=True)
        if msg_type == RPCAP_MSG_PACKET:
            return unpack_packet_header(payload)
        if msg_type == RPCAP_MSG_ERROR:
            raise RuntimeError(self._format_error("RPCAP error during capture", value, payload))
        # Ignore other message types.
        return None

    def _ensure_connected(self) -> None:
        if self._sock is None:
            raise RuntimeError("RPCAP socket is not connected")

    def _send(self, msg_type: int, value: int, payload: bytes) -> None:
        assert self._sock is not None
        hdr = pack_header(msg_type, value, len(payload))
        self._sock.sendall(hdr + payload)

    def _recv_exact(self, n: int, *, from_data: bool = False) -> bytes:
        sock = self._data_sock if from_data and self._data_sock is not None else self._sock
        assert sock is not None
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("RPCAP connection closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _recv_msg(self, *, from_data: bool = False) -> tuple[int, int, bytes]:
        hdr_bytes = self._recv_exact(8, from_data=from_data)
        hdr = unpack_header(hdr_bytes)
        if hdr.ver != 0:
            raise RuntimeError(f"Unsupported RPCAP version: {hdr.ver}")
        payload = self._recv_exact(hdr.plen, from_data=from_data) if hdr.plen else b""
        return hdr.msg_type, hdr.value, payload

    def _format_error(self, prefix: str, code: int, payload: bytes) -> str:
        msg = ""
        if payload:
            try:
                msg = payload.decode("utf-8", errors="ignore").strip()
            except Exception:
                msg = ""
        if msg:
            return f"{prefix} (error={code}): {msg}"
        return f"{prefix} (error={code})"
