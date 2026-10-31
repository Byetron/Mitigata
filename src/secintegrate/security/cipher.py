"""AES-256-GCM. Blob layout: 12-byte random nonce, then ciphertext with the auth tag."""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError
from .secret import Secret

NONCE_BYTES = 12
TAG_BYTES = 16


class AesGcmCipher:
    def encrypt(self, key: bytes, name: str, plaintext: str) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        sealed = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), name.encode("utf-8"))
        return nonce + sealed

    def decrypt(self, key: bytes, name: str, blob: bytes) -> Secret:
        if len(blob) < NONCE_BYTES + TAG_BYTES:
            raise DecryptionError(f"Stored value for {name} is corrupt.")
        nonce, sealed = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
        try:
            plain = AESGCM(key).decrypt(nonce, sealed, name.encode("utf-8"))
        except InvalidTag as exc:
            raise DecryptionError(
                f"Could not decrypt {name}. The value was tampered with, moved, or the master key changed."
            ) from exc
        return Secret(plain.decode("utf-8"))
