"""Settings the web app receives from the composition root."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from ..config.schema import ConnectorConfig
from .google import GoogleCredentials


@dataclass
class ConnectorHooks:
    """Lets the web UI change what the running scheduler does, so no restart is needed."""

    added: Callable[[ConnectorConfig], None]
    removed: Callable[[str], None]


def _no_google() -> GoogleCredentials | None:
    return None


@dataclass
class WebOptions:
    require_login: bool = True  # turned off only by tests
    session_secret: str = ""
    google: Callable[[], GoogleCredentials | None] = _no_google
    hooks: ConnectorHooks | None = None
    transport: httpx.BaseTransport | None = field(default=None, repr=False)  # tests mock Google with this
