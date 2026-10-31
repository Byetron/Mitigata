"""Encrypted secret storage (Feature A)."""
from __future__ import annotations

from .errors import (
    DecryptionError,
    InvalidSecretNameError,
    KeyStoreUnavailableError,
    SecIntegrateError,
    SecretNotFoundError,
)
from .secret import Secret
from .vault import SecretVault

__all__ = [
    "DecryptionError",
    "InvalidSecretNameError",
    "KeyStoreUnavailableError",
    "SecIntegrateError",
    "Secret",
    "SecretNotFoundError",
    "SecretVault",
]
