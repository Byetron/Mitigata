"""Logging with a redaction filter so secret values never reach a log line."""
from __future__ import annotations

import logging
import traceback
from pathlib import Path

from .secrets import redact


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = "".join(traceback.format_exception(*record.exc_info))
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def setup_logging(log_dir: str | Path | None = "logs", level: int = logging.INFO) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(Path(log_dir) / "secintegrate.log", encoding="utf-8"))
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in handlers:
        h.setFormatter(fmt)
        h.addFilter(RedactingFilter())
        root.addHandler(h)
    root.setLevel(level)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
