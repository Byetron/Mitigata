"""Master key backends: OS keychain, environment variable, in-memory (tests)."""
from __future__ import annotations

import os
from collections.abc import Mapping

import keyring
from keyring.errors import KeyringError

from .errors import KeyStoreUnavailableError
from .ports import KeyBackend

MASTER_KEY_ENV = "SECINTEGRATE_MASTER_KEY"
_FIX = "Set SECINTEGRATE_MASTER_KEY, or run `secintegrate init` on a machine with an OS keychain."


class OsKeyringBackend:
    """Uses the OS keychain (Windows Credential Manager, macOS Keychain, Secret Service)."""

    def get(self, service: str, account: str) -> str | None:
        try:
            return keyring.get_password(service, account)
        except KeyringError as exc:
            raise KeyStoreUnavailableError(f"The OS keychain is not available. {_FIX}") from exc

    def set(self, service: str, account: str, value: str) -> None:
        try:
            keyring.set_password(service, account, value)
        except KeyringError as exc:
            raise KeyStoreUnavailableError(f"The OS keychain is not available. {_FIX}") from exc


class EnvKeyBackend:
    """Reads the master key from SECINTEGRATE_MASTER_KEY. Read-only."""

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self._env = os.environ if env is None else env

    def get(self, service: str, account: str) -> str | None:
        return self._env.get(MASTER_KEY_ENV) or None

    def set(self, service: str, account: str, value: str) -> None:
        raise KeyStoreUnavailableError(f"{MASTER_KEY_ENV} is read-only and cannot be changed from here.")


class InMemoryKeyBackend:
    """Keeps the key in a dict. For tests only."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self._data.get((service, account))

    def set(self, service: str, account: str, value: str) -> None:
        self._data[(service, account)] = value


def default_backend(env: Mapping[str, str] | None = None) -> KeyBackend:
    """The environment variable wins when set; otherwise the OS keychain."""
    source = os.environ if env is None else env
    if source.get(MASTER_KEY_ENV):
        return EnvKeyBackend(source)
    return OsKeyringBackend()
