"""Interfaces (ports) for secret storage. Core code depends on these, never on adapters."""
from __future__ import annotations

from typing import Protocol

from .secret import Secret


class KeyBackend(Protocol):
    """Stores the master key somewhere (OS keychain, environment, memory)."""

    def get(self, service: str, account: str) -> str | None: ...

    def set(self, service: str, account: str, value: str) -> None: ...


class Cipher(Protocol):
    def encrypt(self, key: bytes, name: str, plaintext: str) -> bytes: ...

    def decrypt(self, key: bytes, name: str, blob: bytes) -> Secret: ...


class SecretRepository(Protocol):
    def put(self, name: str, blob: bytes) -> None: ...

    def get(self, name: str) -> bytes: ...

    def delete(self, name: str) -> None: ...

    def names(self) -> list[str]: ...

    def entries(self) -> list[tuple[str, str]]: ...
