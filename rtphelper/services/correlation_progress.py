from __future__ import annotations

import contextlib
import contextvars
from typing import Callable, Dict, Iterator, Optional

ProgressEmitter = Callable[[Dict[str, str]], None]

_progress_emitter_var: contextvars.ContextVar[Optional[ProgressEmitter]] = contextvars.ContextVar(
    "progress_emitter", default=None
)


@contextlib.contextmanager
def progress_emitter_context(emitter: Optional[ProgressEmitter]) -> Iterator[None]:
    token = _progress_emitter_var.set(emitter)
    try:
        yield
    finally:
        _progress_emitter_var.reset(token)


def emit_progress(message: str, step: str = "correlation", level: str = "info") -> None:
    emitter = _progress_emitter_var.get()
    if emitter is None:
        return
    try:
        emitter(
            {
                "message": str(message),
                "step": str(step or "correlation"),
                "level": str(level or "info"),
            }
        )
    except Exception:
        # Progress forwarding must never break correlation execution.
        return
