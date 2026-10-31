"""Google sign-in (OAuth 2.0 authorization-code flow with PKCE), built on httpx so no new dependency is needed.

The sign-in code is exchanged server to server over TLS, then Google's userinfo endpoint is asked who the user is.
Only an address Google marks as verified is accepted. Tokens are never logged or stored.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - a URL, not a credential
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
TIMEOUT = 10.0


class GoogleAuthError(Exception):
    """Sign-in failed. The message is safe to show: it never contains tokens or codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class GoogleCredentials:
    client_id: str
    client_secret: str = field(repr=False)


def new_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def authorization_url(creds: GoogleCredentials, redirect_uri: str, state: str, challenge: str) -> str:
    query = urlencode({
        "client_id": creds.client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": "openid email", "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256", "prompt": "select_account",
    })
    return f"{AUTH_URL}?{query}"


def fetch_verified_email(creds: GoogleCredentials, redirect_uri: str, code: str, verifier: str,
                         transport: httpx.BaseTransport | None = None) -> str:
    """Trade the one-time code for the user's verified email address."""
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport) as client:
            token = client.post(TOKEN_URL, data={
                "client_id": creds.client_id, "client_secret": creds.client_secret, "code": code,
                "code_verifier": verifier, "redirect_uri": redirect_uri, "grant_type": "authorization_code",
            })
            if token.status_code != httpx.codes.OK:
                raise GoogleAuthError("failed", "Google did not accept the sign-in. Try again.")
            access_token = token.json().get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise GoogleAuthError("failed", "Google did not accept the sign-in. Try again.")
            info = client.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
            if info.status_code != httpx.codes.OK:
                raise GoogleAuthError("failed", "Could not read your Google profile. Try again.")
            profile = info.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise GoogleAuthError("failed", "Could not reach Google. Check your connection and try again.") from exc
    email = profile.get("email")
    if profile.get("email_verified") is not True or not isinstance(email, str) or "@" not in email:
        raise GoogleAuthError("unverified", "That Google account's email address is not verified.")
    return email.strip().lower()
