"""The vault: validates names, encrypts on store, decrypts on load."""
from __future__ import annotations

import re

from ..secrets import register
from .errors import InvalidSecretNameError
from .master_key import MasterKeyProvider
from .ports import Cipher, SecretRepository
from .secret import Secret

NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def check_name(name: str) -> str:
    if not NAME_RE.match(name):
        raise InvalidSecretNameError(
            "Secret names use capital letters, digits and underscores, and start with a letter. "
            "Example: GITHUB_TOKEN."
        )
    return name


class SecretVault:
    def __init__(self, master: MasterKeyProvider, cipher: Cipher, repo: SecretRepository) -> None:
        self._master = master
        self._cipher = cipher
        self._repo = repo

    def store(self, name: str, value: str) -> None:
        check_name(name)
        if not value:
            raise ValueError("A secret value must not be empty.")
        register(value)
        self._repo.put(name, self._cipher.encrypt(self._master.get_or_create(), name, value))

    def load(self, name: str) -> Secret:
        check_name(name)
        secret = self._cipher.decrypt(self._master.get_or_create(), name, self._repo.get(name))
        register(secret.reveal())  # from now on the redaction filter scrubs this value from logs
        return secret

    def delete(self, name: str) -> None:
        self._repo.delete(check_name(name))

    def list_names(self) -> list[str]:
        return self._repo.names()

    def entries(self) -> list[tuple[str, str]]:
        return self._repo.entries()

    def init_key(self) -> None:
        """Create the master key if it does not exist yet. Idempotent."""
        self._master.get_or_create()
