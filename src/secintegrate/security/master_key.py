"""Creates and reads the 32-byte master key (stored as 64 hex characters)."""
from __future__ import annotations

import os

from .errors import KeyStoreUnavailableError
from .ports import KeyBackend

SERVICE = "secintegrate"
ACCOUNT = "master"
KEY_BYTES = 32
_BAD_KEY = (
    "The master key is missing or malformed. Set SECINTEGRATE_MASTER_KEY to 64 hex characters, "
    "or run `secintegrate init`."
)


class MasterKeyProvider:
    def __init__(self, backend: KeyBackend) -> None:
        self._backend = backend
        self._key: bytes | None = None

    def get_or_create(self) -> bytes:
        if self._key is not None:
            return self._key
        raw = self._backend.get(SERVICE, ACCOUNT)
        if raw is None:
            key = os.urandom(KEY_BYTES)
            self._backend.set(SERVICE, ACCOUNT, key.hex())
        else:
            key = self._parse(raw)
        self._key = key
        return key

    @staticmethod
    def _parse(raw: str) -> bytes:
        try:
            key = bytes.fromhex(raw.strip())
        except ValueError:
            raise KeyStoreUnavailableError(_BAD_KEY) from None
        if len(key) != KEY_BYTES:
            raise KeyStoreUnavailableError(_BAD_KEY)
        return key
