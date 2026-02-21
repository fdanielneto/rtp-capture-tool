from __future__ import annotations

import logging

from rtphelper.logging_setup import setup_logging

LOGGER = logging.getLogger(__name__)


def configure_logging() -> None:
    # Backward-compatible alias for older imports.
    LOGGER.debug("configure_logging alias invoked", extra={"category": "CONFIG"})
    setup_logging()
