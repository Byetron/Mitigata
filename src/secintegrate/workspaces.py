"""One workspace per account: its own connectors, records, health history and stored keys.

Isolation is by file, not by a filter: every account except the first gets its own folder with its own database, so
one account's queries, connectors and keys cannot reach another's. The first account keeps the connectors and keys
that existed before accounts were introduced (the "legacy" workspace).
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import App, build_app
from .notify import Notifier
from .security.ports import KeyBackend
from .storage.db import Database
from .web.options import WebContext

OWNER_SETTING = "workspace_owner"


def user_slug(email: str) -> str:
    """A folder name that is safe whatever the email contains (no dots, slashes or odd characters)."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:20]


@dataclass(frozen=True)
class Workspace:
    owner: str
    config_dir: Path
    db_path: Path
    legacy: bool


class WorkspaceManager:
    def __init__(
        self,
        system_db: Database,
        legacy_config_dir: Path,
        legacy_db_path: Path,
        base_dir: Path | None = None,
        backend: KeyBackend | None = None,
        notifier: Notifier | None = None,
    ) -> None:
        self.system_db = system_db
        self._legacy_config_dir = legacy_config_dir
        self._legacy_db_path = legacy_db_path
        # new accounts' folders sit next to the main database, so a test or a second install never shares them
        self._base = base_dir if base_dir is not None else legacy_db_path.parent / "workspaces"
        self._backend = backend
        self._notifier = notifier
        self._apps: dict[str, App] = {}
        self._lock = threading.Lock()

    def legacy_owner(self) -> str | None:
        """Who owns the pre-existing connectors: the earliest account, remembered once chosen.

        If that account is later removed nobody inherits them silently; they stay unowned.
        """
        owner = self.system_db.get_setting(OWNER_SETTING)
        if owner is not None:
            return owner if self.system_db.get_app_user(owner) else None
        accounts = self.system_db.list_app_users()
        if not accounts:
            return None
        first = str(accounts[0]["email"])
        self.system_db.set_setting(OWNER_SETTING, first)
        return first

    def is_legacy(self, email: str) -> bool:
        return self.legacy_owner() == email.strip().lower()

    def workspace(self, email: str) -> Workspace:
        address = email.strip().lower()
        if self.is_legacy(address):
            return Workspace(address, self._legacy_config_dir, self._legacy_db_path, True)
        root = self._base / user_slug(address)
        config_dir = root / "connectors"
        config_dir.mkdir(parents=True, exist_ok=True)
        return Workspace(address, config_dir, root / "secintegrate.db", False)

    def app_for(self, email: str) -> App:
        address = email.strip().lower()
        with self._lock:
            if address not in self._apps:
                ws = self.workspace(address)
                self._apps[address] = build_app(ws.config_dir, ws.db_path, self._backend, self._notifier)
            return self._apps[address]

    def web_context(self, email: str) -> WebContext:
        app = self.app_for(email)
        return WebContext(app.config_dir, app.db, app.vault.list_names)
