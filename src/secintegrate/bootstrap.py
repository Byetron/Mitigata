"""Composition root (brief X-4): the one place that chooses concrete adapters."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .notify import CompositeNotifier, LogNotifier, Notifier, WebhookNotifier
from .security.errors import SecretNotFoundError
from .security.factory import build_vault, default_db_path
from .security.ports import KeyBackend
from .security.vault import SecretVault
from .storage.db import Database

WEBHOOK_SECRET = "NOTIFY_WEBHOOK_URL"  # noqa: S105 - the NAME of a secret, not a value


@dataclass
class App:
    config_dir: Path
    db: Database
    vault: SecretVault
    notifier: Notifier


def build_app(
    config_dir: Path = Path("config/connectors"),
    db_path: Path | None = None,
    backend: KeyBackend | None = None,
    notifier: Notifier | None = None,
) -> App:
    """Wire the database, vault and notifier. The CLI, scheduler and web server all start here."""
    path = db_path if db_path is not None else default_db_path()
    db = Database(path)
    vault = build_vault(path, backend)

    def webhook_url() -> str | None:
        try:
            return vault.load(WEBHOOK_SECRET).reveal()
        except SecretNotFoundError:
            return None

    chosen = notifier if notifier is not None else CompositeNotifier([LogNotifier(), WebhookNotifier(webhook_url)])
    return App(config_dir=Path(config_dir), db=db, vault=vault, notifier=chosen)
