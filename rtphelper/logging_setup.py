from __future__ import annotations

import contextlib
import contextvars
import logging
import os
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterator, Optional

LOG_FILE = Path("logs/app.log")
ACCESS_LOG_FILE = Path("logs/access.log")
DEFAULT_CATEGORY = "CONFIG"
CATEGORIES = {
    "CAPTURE",
    "SIP",
    "SDP",
    "SDES_KEYS",
    "SRTP_DECRYPT",
    "RTP_SEARCH",
    "FILES",
    "PERF",
    "CONFIG",
    "ERRORS",
}

# Propagated automatically within async tasks; threads must re-set explicitly.
_correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")
_category_var: contextvars.ContextVar[str] = contextvars.ContextVar("category", default=DEFAULT_CATEGORY)


def short_uuid() -> str:
    return uuid.uuid4().hex[:8]


def get_correlation_id() -> str:
    return _correlation_id_var.get()


def get_category() -> str:
    return _category_var.get()


@contextlib.contextmanager
def correlation_context(correlation_id: Optional[str] = None) -> Iterator[None]:
    token = _correlation_id_var.set(correlation_id or short_uuid())
    try:
        yield
    finally:
        _correlation_id_var.reset(token)


@contextlib.contextmanager
def category_context(category: str) -> Iterator[None]:
    token = _category_var.set(category if category in CATEGORIES else DEFAULT_CATEGORY)
    try:
        yield
    finally:
        _category_var.reset(token)


@contextlib.contextmanager
def log_context(category: Optional[str] = None, correlation_id: Optional[str] = None) -> Iterator[None]:
    tokens = []
    try:
        if category is not None:
            tokens.append(("category", _category_var.set(category)))
        if correlation_id is not None:
            tokens.append(("cid", _correlation_id_var.set(correlation_id)))
        yield
    finally:
        # Reset in reverse order.
        for key, token in reversed(tokens):
            if key == "category":
                _category_var.reset(token)
            else:
                _correlation_id_var.reset(token)


class ContextEnricherFilter(logging.Filter):
    """
    Ensures every LogRecord has:
      - category
      - correlation_id
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if not hasattr(record, "category") or not getattr(record, "category"):
            record.category = get_category()
        if not hasattr(record, "correlation_id") or not getattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id()
        return True


class CategoryLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, logger: logging.Logger, category: str) -> None:
        super().__init__(logger, extra={"category": category})

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})
        if "category" not in extra:
            extra["category"] = self.extra.get("category") or get_category()
        if "correlation_id" not in extra:
            extra["correlation_id"] = get_correlation_id()
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logging() -> None:
    """
    Central logging setup.

    Format (mandatory):
      %(asctime)s | %(levelname)s | %(category)s | cid=%(correlation_id)s | %(name)s |
      %(filename)s:%(lineno)d %(funcName)s() | %(message)s
    """
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACCESS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    fmt = (
        "%(asctime)s | %(levelname)s | %(category)s | cid=%(correlation_id)s | %(name)s | "
        "%(filename)s:%(lineno)d %(funcName)s() | %(message)s"
    )
    # Important: do NOT pass datefmt; default includes ",%03d" milliseconds.
    formatter = logging.Formatter(fmt=fmt)
    access_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s"
    )

    level_name = os.environ.get("RTPHELPER_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    external_level_name = os.environ.get("RTPHELPER_EXTERNAL_LIB_LOG_LEVEL", "WARNING").upper()
    external_level = getattr(logging, external_level_name, logging.WARNING)

    root_logger = logging.getLogger()

    # Avoid double-installation; still allow runtime level update.
    if getattr(root_logger, "_rtphelper_logging_installed", False):
        root_logger.setLevel(level)
        for h in root_logger.handlers:
            h.setLevel(level)
        access_logger = logging.getLogger("rtphelper.access")
        access_level_name = os.environ.get("RTPHELPER_ACCESS_LOG_LEVEL", "INFO").upper()
        access_level = getattr(logging, access_level_name, logging.INFO)
        access_logger.setLevel(access_level)
        for noisy in ("botocore", "boto3", "s3transfer", "urllib3", "asyncio"):
            logging.getLogger(noisy).setLevel(external_level)
        return
    root_logger.setLevel(level)

    enricher = ContextEnricherFilter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(enricher)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(enricher)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    access_logger = logging.getLogger("rtphelper.access")
    access_logger.propagate = False
    access_level_name = os.environ.get("RTPHELPER_ACCESS_LOG_LEVEL", "INFO").upper()
    access_level = getattr(logging, access_level_name, logging.INFO)
    access_logger.setLevel(access_level)
    access_file_handler = RotatingFileHandler(
        ACCESS_LOG_FILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    access_file_handler.setFormatter(access_formatter)
    access_logger.handlers = [access_file_handler]
    for noisy in ("botocore", "boto3", "s3transfer", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(external_level)
    root_logger._rtphelper_logging_installed = True  # type: ignore[attr-defined]


def get_logger(name: str, category: str = DEFAULT_CATEGORY) -> CategoryLoggerAdapter:
    return CategoryLoggerAdapter(logging.getLogger(name), category if category in CATEGORIES else DEFAULT_CATEGORY)


def get_access_logger() -> logging.Logger:
    return logging.getLogger("rtphelper.access")
