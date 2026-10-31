"""Sign-in for the web UI: Google (preferred) or a local password, plus CSRF protection and safe headers."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, session
from werkzeug.wrappers import Response as WerkzeugResponse

from ..storage.db import Database
from . import google
from .options import WebOptions

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 10
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
PUBLIC_ENDPOINTS = {"login", "login_post", "signup", "signup_post", "google_start", "google_callback"}
SESSION_HOURS = 8
GOOGLE_ERRORS = {
    "denied": "Google sign-in was cancelled.",
    "state": "The sign-in session expired. Please try again.",
    "failed": "Google sign-in failed. Please try again.",
    "unverified": "That Google account's email address is not verified.",
    "notallowed": "That Google account could not be added. Ask an existing user to run `hermes auth add EMAIL`.",
    "pending": "Your request is waiting for approval by someone who already has access.",
}
PENDING_NOTICE = ("Thanks. If this address can be registered, it will be able to sign in as soon as someone who "
                  "already has access approves it.")


# --- passwords -----------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r),
                                p=int(p), dklen=len(bytes.fromhex(digest_hex)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, bytes.fromhex(digest_hex))


_DUMMY_HASH = hash_password("not-a-real-password")  # burns the same time when the email is unknown


class LoginThrottle:
    """Blocks a key after too many failures in a window. In memory: it resets when Hermes restarts."""

    def __init__(self, max_failures: int = 5, window_seconds: float = 600.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._max, self._window, self._clock = max_failures, window_seconds, clock
        self._failures: dict[str, list[float]] = {}

    def _recent(self, key: str) -> list[float]:
        now = self._clock()
        kept = [t for t in self._failures.get(key, []) if now - t < self._window]
        self._failures[key] = kept
        return kept

    def blocked(self, *keys: str) -> bool:
        return any(len(self._recent(k)) >= self._max for k in keys)

    def fail(self, *keys: str) -> None:
        for k in keys:
            self._recent(k).append(self._clock())

    def clear(self, *keys: str) -> None:
        for k in keys:
            self._failures.pop(k, None)


def safe_next(target: str | None) -> str:
    """Only same-site paths: never redirect a signed-in user to another site."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


def register_auth(app: Flask, db: Database, options: WebOptions) -> None:
    throttle = LoginThrottle()
    app.secret_key = options.session_secret or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME="hermes_session",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS), MAX_CONTENT_LENGTH=256 * 1024,
    )

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return str(session["csrf"])

    @app.context_processor
    def inject() -> dict[str, Any]:
        return {"csrf_token": csrf_token, "current_user": session.get("user")}

    canonical = urlparse(options.public_url).netloc if options.public_url else ""

    @app.before_request
    def guard() -> WerkzeugResponse | Response | None:
        if canonical and request.method == "GET" and request.host != canonical:
            # cookies belong to one host name: send people to the address Google was told about
            return redirect(f"{options.public_url}{request.full_path.rstrip('?')}")
        if not options.require_login:
            g.user = None
            return None
        if request.method == "POST":
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
            if not hmac.compare_digest(sent, str(session.get("csrf", ""))) or not session.get("csrf"):
                abort(400, "Your session expired. Reload the page and try again.")
        if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint == "static":
            return None
        account = db.get_app_user(session["user"]) if session.get("user") else None
        if account is None or account["status"] != "active":
            session.clear()  # removed or not yet approved: the session stops working at once
            if request.method != "GET" or request.path.startswith("/connectors/validate"):
                abort(401)
            return redirect(f"/login?next={request.path}")
        g.user = session["user"]
        return None

    @app.after_request
    def secure_headers(resp: Response) -> Response:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.errorhandler(400)
    @app.errorhandler(401)
    def reject(error: Any) -> tuple[Response, int]:
        message = getattr(error, "description", "Not allowed.")
        status = int(getattr(error, "code", 400))
        if request.path.startswith("/connectors/validate"):
            return jsonify(error=message), status
        return Response(message, status=status, mimetype="text/plain"), status

    def sign_in(email: str) -> WerkzeugResponse:
        session.clear()  # new session id on every sign-in
        session.permanent = True
        session["user"] = email
        csrf_token()
        return redirect(safe_next(request.args.get("next") or request.form.get("next")))

    def login_page(error: str | None = None, status: int = 200) -> tuple[str, int]:
        return render_template("login.html", error=error, google_enabled=options.google() is not None,
                               next=safe_next(request.args.get("next")), page="login"), status

    @app.get("/login")
    def login() -> tuple[str, int] | WerkzeugResponse:
        if session.get("user"):
            return redirect("/")
        return login_page(GOOGLE_ERRORS.get(request.args.get("error", "")))

    @app.post("/login")
    def login_post() -> tuple[str, int] | WerkzeugResponse:
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        keys = (f"user:{email}", f"ip:{request.remote_addr}")
        if throttle.blocked(*keys):
            return login_page("Too many failed attempts. Wait 10 minutes and try again.", 429)
        user = db.get_app_user(email) if EMAIL_RE.match(email) else None
        stored = (user or {}).get("password_hash")
        good = verify_password(password, stored or _DUMMY_HASH) and bool(stored)
        if not good:
            throttle.fail(*keys)
            return login_page("Wrong email or password.", 401)
        throttle.clear(*keys)
        if (user or {}).get("status") != "active":  # only reached with the right password
            return login_page("Your account is waiting for approval by someone who already has access.", 403)
        return sign_in(email)

    @app.post("/logout")
    def logout() -> WerkzeugResponse:
        session.clear()
        return redirect("/login")

    def redirect_uri() -> str:
        return (options.public_url or request.url_root).rstrip("/") + "/auth/callback"

    @app.get("/auth/google")
    def google_start() -> WerkzeugResponse:
        creds = options.google()
        if creds is None:
            return redirect("/login")
        verifier, challenge = google.new_pkce()
        state = secrets.token_urlsafe(24)
        session["oauth"] = {"state": state, "verifier": verifier}
        return redirect(google.authorization_url(creds, redirect_uri(), state, challenge))

    @app.get("/auth/callback")
    def google_callback() -> WerkzeugResponse:
        pending = session.pop("oauth", None)
        creds = options.google()

        def fail(code: str) -> WerkzeugResponse:
            return redirect(f"/login?error={code}")

        if request.args.get("error"):
            return fail("denied")
        sent_state = request.args.get("state", "")
        if (not pending or creds is None or not hmac.compare_digest(sent_state, str(pending.get("state", "")))
                or not request.args.get("code")):
            return fail("state")
        try:
            email = google.fetch_verified_email(creds, redirect_uri(), request.args["code"], pending["verifier"],
                                                options.transport)
        except google.GoogleAuthError as exc:
            return fail(exc.code)
        user = db.get_app_user(email)
        if user is None:  # first sign-in: the first account is active, later ones wait for approval
            if db.create_app_user(email, None) == "full":
                return fail("notallowed")
            user = db.get_app_user(email)
        if user is None or user["status"] != "active":
            return fail("pending")
        return sign_in(email)

    # --- creating an account -------------------------------------------------------------------
    def signup_page(error: str | None = None, notice: str | None = None, status: int = 200,
                    email: str = "") -> tuple[str, int]:
        return render_template("signup.html", error=error, notice=notice, email=email, page="login",
                               google_enabled=options.google() is not None,
                               min_length=MIN_PASSWORD_LENGTH), status

    @app.get("/signup")
    def signup() -> tuple[str, int] | WerkzeugResponse:
        if session.get("user"):
            return redirect("/")
        return signup_page()

    @app.post("/signup")
    def signup_post() -> tuple[str, int] | WerkzeugResponse:  # noqa: PLR0911 - one page per distinct outcome
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        key = f"signup:{request.remote_addr}"
        if throttle.blocked(key):
            return signup_page("Too many attempts. Wait 10 minutes and try again.", status=429, email=email)
        throttle.fail(key)  # every attempt counts, so this cannot be used to create accounts in bulk
        if not EMAIL_RE.match(email):
            return signup_page("Enter a valid email address.", status=400, email=email)
        if len(password) < MIN_PASSWORD_LENGTH:
            return signup_page(f"Use at least {MIN_PASSWORD_LENGTH} characters for the password.", status=400,
                               email=email)
        if password != (request.form.get("confirm") or ""):
            return signup_page("The two passwords do not match.", status=400, email=email)
        outcome = db.create_app_user(email, hash_password(password))
        if outcome == "active":  # the first account ever
            return sign_in(email)
        if outcome == "full":
            return signup_page("Too many requests are waiting. Ask someone with access to review them first.",
                               status=429, email=email)
        return signup_page(notice=PENDING_NOTICE)  # same answer for new and existing addresses
