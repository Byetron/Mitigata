"""Settings the web app receives from the composition root."""
from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..config.schema import ConnectorConfig
from ..storage.db import Database
from .google import GoogleCredentials

SecretNames = Callable[[], Collection[str]]


@dataclass
class WebContext:
    """Everything one account's pages work on: its connectors folder, its database, the names of its keys."""

    config_dir: Path
    db: Database
    secret_names: SecretNames | None = None


@dataclass
class ConnectorHooks:
    """Lets the web UI change what the running scheduler does, so no restart is needed.

    Both receive the signed-in account's email first ("" when there are no accounts).
    """

    added: Callable[[str, ConnectorConfig], None]
    removed: Callable[[str, str], None]
    run_now: Callable[[str, str], object] | None = None  # (account, connector): run it again about a second from now


def _no_google() -> GoogleCredentials | None:
    return None


@dataclass
class WebOptions:
    require_login: bool = True  # turned off only by tests
    session_secret: str = ""
    google: Callable[[], GoogleCredentials | None] = _no_google
    hooks: ConnectorHooks | None = None
    public_url: str | None = None  # e.g. http://127.0.0.1:8000: the one address Google redirects back to
    workspaces: Callable[[str], WebContext] | None = None  # account email -> that account's own context
    transport: httpx.BaseTransport | None = field(default=None, repr=False)  # tests mock Google with this
