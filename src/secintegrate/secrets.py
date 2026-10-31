"""Resolve secrets from environment variables and track them for redaction (FR-6)."""
from __future__ import annotations

import os
import threading

_lock = threading.Lock()
_registered: set[str] = set()


class MissingSecret(Exception):
    """An environment variable that a config refers to is unset or empty."""


def register(value: str | None) -> None:
    """Remember a secret value so that redact() can scrub it from any text."""
    if value and len(value) >= 4:
        with _lock:
            _registered.add(value)


def redact(text: str) -> str:
    with _lock:
        values = sorted(_registered, key=len, reverse=True)
    for v in values:
        if v in text:
            text = text.replace(v, "***")
    return text


def get_secret(name: str) -> str:
    """Read the value at request time. Only the NAME ever appears in errors."""
    value = os.environ.get(name)
    if not value:
        raise MissingSecret(name)
    register(value)
    return value


def clear() -> None:
    with _lock:
        _registered.clear()
