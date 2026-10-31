"""Error types for secret storage. Messages never contain secret values."""
from __future__ import annotations


class SecIntegrateError(Exception):
    """Base class for all platform errors that are safe to show to a user."""


class KeyStoreUnavailableError(SecIntegrateError):
    """The master key cannot be read, created or parsed."""


class SecretNotFoundError(SecIntegrateError):
    """No secret is stored under this name."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Secret {name} is not stored. Run `secintegrate secret set {name}`.")
        self.name = name


class DecryptionError(SecIntegrateError):
    """Ciphertext is corrupt, tampered with, or was moved to another name."""


class InvalidSecretNameError(SecIntegrateError):
    """Secret names must look like environment variable names, for example GITHUB_TOKEN."""
