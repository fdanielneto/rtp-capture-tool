from __future__ import annotations

import logging
import os
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def _parse_env_line(line: str) -> tuple[str, str] | None:
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    if text.startswith("export "):
        text = text[len("export ") :].strip()
    if "=" not in text:
        return None
    key, value = text.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    return key, value


def load_env_file(path: Path, override: bool = False) -> int:
    if not path.exists():
        return 0
    loaded = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(raw_line)
        if not parsed:
            continue
        key, value = parsed
        if override or key not in os.environ:
            os.environ[key] = value
            loaded += 1
    LOGGER.info("Loaded env file path=%s keys=%s", path, loaded, extra={"category": "CONFIG"})
    return loaded

