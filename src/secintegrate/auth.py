"""Auth header builders (FR-1). Secrets are read from the environment at request time."""
from __future__ import annotations

import base64

from .secrets import get_secret, register


def build_auth_headers(auth) -> dict[str, str]:
    kind = auth.type
    if kind == "none":
        return {}
    if kind == "bearer":
        return {"Authorization": f"Bearer {get_secret(auth.secret)}"}
    if kind == "basic":
        user = get_secret(auth.username_env)
        password = get_secret(auth.secret)
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        register(token)
        return {"Authorization": f"Basic {token}"}
    if kind == "api_key_header":
        return {auth.header: get_secret(auth.secret)}
    raise ValueError(f"unknown auth type {kind}")


def secret_env_names(auth) -> list[str]:
    return [n for n in (getattr(auth, "username_env", None), getattr(auth, "secret", None)) if n]
