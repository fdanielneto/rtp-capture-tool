from __future__ import annotations

import logging
import struct
import threading
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

LOGGER = logging.getLogger(__name__)

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4


@dataclass
class RollingPcapWriter:
    base_dir: Path
    file_prefix: str
    max_bytes: int
    max_seconds: int
    linktype: int
    snaplen: int

    _lock: threading.Lock = threading.Lock()
    _fh: Optional[object] = None
    _seq: int = 0
    _bytes_written: int = 0
    _seq_initialized: bool = False
    _current_path: Optional[Path] = None
    _opened_monotonic: float = 0.0

    def _init_seq_from_existing(self) -> None:
        if self._seq_initialized:
            return
        self.base_dir.mkdir(parents=True, exist_ok=True)
        pattern = re.compile(rf"^{re.escape(self.file_prefix)}-(\d{{4}})\.pcap$", re.IGNORECASE)
        max_seq = 0
        for p in self.base_dir.glob(f"{self.file_prefix}-*.pcap"):
            m = pattern.match(p.name)
            if not m:
                continue
            try:
                n = int(m.group(1))
            except Exception:
                continue
            if n > max_seq:
                max_seq = n
        self._seq = max_seq
        self._seq_initialized = True

    def open_next(self) -> Path:
        self._init_seq_from_existing()
        self._seq += 1
        out = self.base_dir / f"{self.file_prefix}-{self._seq:04d}.pcap"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._fh = open(out, "wb")
        self._current_path = out
        self._bytes_written = 0
        self._opened_monotonic = time.monotonic()
        self._write_global_header()
        LOGGER.info("Opened rolling pcap file=%s seq=%s", out, self._seq, extra={"category": "FILES"})
        return out

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None
                LOGGER.debug("Closed rolling pcap writer prefix=%s", self.file_prefix, extra={"category": "FILES"})

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes, orig_len: int) -> None:
        with self._lock:
            if self._fh is None:
                self.open_next()

            incl_len = len(data)
            rec = struct.pack("<IIII", int(ts_sec), int(ts_usec), int(incl_len), int(orig_len)) + data

            rotate_by_size = self._bytes_written + len(rec) > self.max_bytes and self._bytes_written > 24
            rotate_by_time = False
            if self.max_seconds > 0 and self._bytes_written > 24:
                rotate_by_time = (time.monotonic() - self._opened_monotonic) >= float(self.max_seconds)

            # Rotate if needed
            if rotate_by_size or rotate_by_time:
                previous_file = self._current_path
                if rotate_by_size:
                    LOGGER.info(
                        "Rolling pcap rotation prefix=%s current_bytes=%s next_record_bytes=%s max_bytes=%s",
                        self.file_prefix,
                        self._bytes_written,
                        len(rec),
                        self.max_bytes,
                        extra={"category": "FILES"},
                    )
                else:
                    LOGGER.info(
                        "Rolling pcap rotation by time prefix=%s current_bytes=%s max_seconds=%s",
                        self.file_prefix,
                        self._bytes_written,
                        self.max_seconds,
                        extra={"category": "FILES"},
                    )
                self._fh.close()
                self._fh = None
                next_file = self.open_next()
                if previous_file is not None:
                    LOGGER.info(
                        "Capture file limit reached previous_file=%s next_file=%s",
                        previous_file.name,
                        next_file.name,
                        extra={"category": "FILES"},
                    )

            assert self._fh is not None
            self._fh.write(rec)
            self._fh.flush()
            self._bytes_written += len(rec)

    def _write_global_header(self) -> None:
        assert self._fh is not None
        hdr = struct.pack(
            "<IHHIIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            int(self.snaplen),
            int(self.linktype),
        )
        self._fh.write(hdr)
        self._fh.flush()
        self._bytes_written += len(hdr)
