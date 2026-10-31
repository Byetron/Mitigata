"""Composition of the vault. This is where concrete adapters are chosen."""
from __future__ import annotations

from pathlib import Path

import platformdirs

from .cipher import AesGcmCipher
from .keybackends import default_backend
from .master_key import MasterKeyProvider
from .ports import KeyBackend
from .repository import SqliteSecretRepository
from .vault import SecretVault


def default_db_path() -> Path:
    """One database per user, shared by the whole platform."""
    return platformdirs.user_data_path("secintegrate", appauthor=False, ensure_exists=True) / "secintegrate.db"


def build_vault(db_path: str | Path | None = None, backend: KeyBackend | None = None) -> SecretVault:
    path = default_db_path() if db_path is None else db_path
    return SecretVault(
        MasterKeyProvider(backend if backend is not None else default_backend()),
        AesGcmCipher(),
        SqliteSecretRepository(path),
    )
