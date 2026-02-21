from __future__ import annotations

import re

_SIZE_PATTERN = re.compile(r"^\s*(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>[a-zA-Z]{0,4})\s*$")
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}


def parse_size_bytes(raw: str | None, default: int) -> int:
    """
    Parse a human-readable size and return bytes.

    Accepted examples: "1048576", "200MB", "100MiB", "1 GB", "1.5GiB".
    Returns default for empty/invalid/non-positive inputs.
    """
    text = (raw or "").strip()
    if not text:
        return default
    match = _SIZE_PATTERN.match(text)
    if not match:
        return default
    try:
        number = float(match.group("num"))
    except Exception:
        return default
    unit = (match.group("unit") or "").lower()
    multiplier = _SIZE_UNITS.get(unit)
    if multiplier is None:
        return default
    value = int(number * multiplier)
    if value <= 0:
        return default
    return value
