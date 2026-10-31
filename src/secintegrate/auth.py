"""Auth header builders (FR-1). Secrets are decrypted from the vault at request time only."""
from __future__ import annotations

import base64

from .config.schema import Auth
from .secrets import register
from .security.ports import SecretLoader


def build_auth_headers(auth: Auth, vault: SecretLoader) -> dict[str, str]:
    kind = auth.type
    if kind == "none":
        return {}
    if kind == "bearer" and auth.secret:
        return {"Authorization": f"Bearer {vault.load(auth.secret).reveal()}"}
    if kind == "basic" and auth.secret and auth.username_env:
        user = vault.load(auth.username_env).reveal()
        password = vault.load(auth.secret).reveal()
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        register(token)
        return {"Authorization": f"Basic {token}"}
    if kind == "api_key_header" and auth.secret and auth.header:
        return {auth.header: vault.load(auth.secret).reveal()}
    raise ValueError(f"incomplete auth settings for type {kind}")


def secret_env_names(auth: Auth) -> list[str]:
    return [n for n in (auth.username_env, auth.secret) if n]
