"""Creating accounts: first-account bootstrap, approval, Google first sign-in, host pinning."""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from flask.testing import FlaskClient
from typer.testing import CliRunner
from werkzeug.test import TestResponse

from secintegrate.cli import app as cli_app
from secintegrate.storage.db import Database
from secintegrate.web.app import create_app
from secintegrate.web.auth import hash_password
from secintegrate.web.google import GoogleCredentials
from secintegrate.web.options import WebOptions
from test_web_auth import CSRF, EMAIL, PASSWORD, Google, start_google

OTHER = "bob@example.com"


@pytest.fixture
def google() -> Google:
    return Google()


def make_client(tmp_path: Path, db: Database, google: Google | None = None,
                public_url: str | None = None) -> FlaskClient:
    options = WebOptions(
        require_login=True, session_secret="s" * 32, public_url=public_url,
        google=lambda: GoogleCredentials("client-id-1", "client-secret-1"),
        transport=httpx.MockTransport((google or Google()).handle),
    )
    return create_app(tmp_path / "cfg", db, None, options).test_client()


def csrf_from(client: FlaskClient, path: str) -> str:
    match = CSRF.search(client.get(path).get_data(as_text=True))
    assert match is not None
    return match.group(1)


def sign_up(client: FlaskClient, email: str, password: str = PASSWORD, confirm: str | None = None) -> TestResponse:
    csrf = csrf_from(client, "/signup")
    return client.post("/signup", data={"email": email, "password": password,
                                        "confirm": password if confirm is None else confirm, "csrf_token": csrf})


# --- database rules ---------------------------------------------------------------------------------
def test_first_account_is_active_and_later_ones_wait(db: Database) -> None:
    assert db.create_app_user(EMAIL, hash_password(PASSWORD)) == "active"
    assert db.create_app_user(OTHER, hash_password(PASSWORD)) == "pending"
    assert db.create_app_user(OTHER, hash_password("another password")) == "exists"  # never overwritten
    assert [u["status"] for u in db.list_app_users()] == ["pending", "active"]  # pending listed first
    assert db.approve_app_user(OTHER) and not db.approve_app_user(OTHER)


def test_pending_requests_are_capped(db: Database) -> None:
    db.create_app_user(EMAIL, None)
    assert db.create_app_user("a@example.com", None, max_pending=1) == "pending"
    assert db.create_app_user("b@example.com", None, max_pending=1) == "full"


def test_old_databases_gain_the_status_column(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE app_users (email TEXT PRIMARY KEY, password_hash TEXT, added_at TEXT NOT NULL)")
    old.execute("INSERT INTO app_users VALUES ('ann@example.com', NULL, '2026-01-01T00:00:00Z')")
    old.commit()
    old.close()
    migrated = Database(path)
    user = migrated.get_app_user("ann@example.com")
    assert user is not None and user["status"] == "active"  # people who could sign in before still can


# --- the sign-up page -------------------------------------------------------------------------------
def test_first_signup_gets_straight_in(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    response = sign_up(client, EMAIL)
    assert response.status_code == 302
    assert EMAIL in client.get("/").get_data(as_text=True)
    user = db.get_app_user(EMAIL)
    assert user is not None and user["status"] == "active" and PASSWORD not in str(user)


def test_later_signups_wait_and_cannot_sign_in(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    client = make_client(tmp_path, db)
    page = sign_up(client, OTHER).get_data(as_text=True)
    assert "waiting" not in page and "approves it" in page  # neutral wording, same for any address
    assert (db.get_app_user(OTHER) or {})["status"] == "pending"
    csrf = csrf_from(client, "/login")
    blocked = client.post("/login", data={"email": OTHER, "password": PASSWORD, "csrf_token": csrf})
    assert blocked.status_code == 403 and "waiting for approval" in blocked.get_data(as_text=True)
    assert client.get("/").status_code == 302  # still signed out


def test_signup_never_changes_an_existing_account(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    before = db.get_app_user(EMAIL)
    client = make_client(tmp_path, db)
    page = sign_up(client, EMAIL, "attacker chosen password").get_data(as_text=True)
    assert "approves it" in page  # the same answer as a brand new address
    assert db.get_app_user(EMAIL) == before


@pytest.mark.parametrize(("email", "password", "confirm", "message"), [
    ("not-an-email", PASSWORD, PASSWORD, "valid email"),
    (OTHER, "short", "short", "at least 10"),
    (OTHER, PASSWORD, "different password", "do not match"),
])
def test_signup_validation(tmp_path: Path, db: Database, email: str, password: str, confirm: str,
                           message: str) -> None:
    client = make_client(tmp_path, db)
    response = sign_up(client, email, password, confirm)
    assert response.status_code == 400 and message in response.get_data(as_text=True)
    assert db.list_app_users() == []


def test_signup_is_throttled_and_needs_a_csrf_token(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert client.post("/signup", data={"email": OTHER, "password": PASSWORD, "confirm": PASSWORD}).status_code == 400
    for i in range(5):
        sign_up(client, f"user{i}@example.com", "short", "short")
    assert sign_up(client, OTHER).status_code == 429


# --- approval ---------------------------------------------------------------------------------------
def test_an_existing_user_approves_a_request(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    waiting = make_client(tmp_path, db)
    sign_up(waiting, OTHER)
    admin = make_client(tmp_path, db)
    csrf = csrf_from(admin, "/login")
    admin.post("/login", data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf})
    page = admin.get("/users").get_data(as_text=True)
    assert OTHER in page and "waiting for approval" in page and "Approve" in page
    assert '<span class="badge">1</span>' in admin.get("/").get_data(as_text=True)
    token = csrf_from(admin, "/users")
    assert admin.post("/users/approve", data={"email": OTHER}).status_code == 400  # no CSRF token
    assert admin.post("/users/approve", data={"email": OTHER, "csrf_token": token}).status_code == 302
    login_csrf = csrf_from(waiting, "/login")
    ok = waiting.post("/login", data={"email": OTHER, "password": PASSWORD, "csrf_token": login_csrf})
    assert ok.status_code == 302 and OTHER in waiting.get("/").get_data(as_text=True)


def test_removing_a_user_signs_them_out_at_once(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    db.create_app_user(OTHER, hash_password(PASSWORD))
    db.approve_app_user(OTHER)
    admin, guest = make_client(tmp_path, db), make_client(tmp_path, db)
    for client, who in ((admin, EMAIL), (guest, OTHER)):
        csrf = csrf_from(client, "/login")
        client.post("/login", data={"email": who, "password": PASSWORD, "csrf_token": csrf})
    assert guest.get("/").status_code == 200
    token = csrf_from(admin, "/users")
    assert admin.post("/users/remove", data={"email": OTHER, "csrf_token": token}).status_code == 302
    assert guest.get("/").status_code == 302  # the session no longer works
    assert admin.post("/users/remove", data={"email": EMAIL, "csrf_token": token}).status_code == 400  # not yourself


def test_users_page_needs_sign_in(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert client.get("/users").status_code == 302
    assert client.post("/users/approve", data={"email": OTHER}).status_code in (400, 401)


# --- Google creating an account ---------------------------------------------------------------------
def google_sign_in(client: FlaskClient, email: str, google: Google) -> str:
    google.email = email
    state = parse_qs(urlparse(start_google(client)).query)["state"][0]
    return str(client.get(f"/auth/callback?state={state}&code=abc").headers["Location"])


def test_first_google_sign_in_creates_the_first_account(tmp_path: Path, db: Database, google: Google) -> None:
    client = make_client(tmp_path, db, google)
    assert google_sign_in(client, EMAIL, google) == "/"
    user = db.get_app_user(EMAIL)
    assert user is not None and user["status"] == "active" and user["password_hash"] is None
    assert EMAIL in client.get("/").get_data(as_text=True)


def test_later_google_accounts_wait_for_approval(tmp_path: Path, db: Database, google: Google) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    client = make_client(tmp_path, db, google)
    assert google_sign_in(client, OTHER, google) == "/login?error=pending"
    assert (db.get_app_user(OTHER) or {})["status"] == "pending"
    assert client.get("/").status_code == 302
    db.approve_app_user(OTHER)
    assert google_sign_in(client, OTHER, google) == "/"


# --- pinning the address Google redirects to -------------------------------------------------------------
def test_other_host_names_are_sent_to_the_canonical_address(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, public_url="http://127.0.0.1:8000")
    moved = client.get("/connectors/new?tab=yaml", headers={"Host": "localhost:8000"})
    assert moved.status_code == 302 and moved.headers["Location"] == "http://127.0.0.1:8000/connectors/new?tab=yaml"
    same = client.get("/login", headers={"Host": "127.0.0.1:8000"})
    assert same.status_code == 200


def test_google_redirect_uri_ignores_the_host_header(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, public_url="http://127.0.0.1:8000")
    response = client.get("/auth/google", headers={"Host": "127.0.0.1:8000", "X-Forwarded-Host": "evil.example"})
    query = parse_qs(urlparse(response.headers["Location"]).query)
    assert query["redirect_uri"] == ["http://127.0.0.1:8000/auth/callback"]


# --- pages and CLI ------------------------------------------------------------------------------------
def test_login_and_signup_pages_link_to_each_other(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert 'href="/signup"' in client.get("/login").get_data(as_text=True)
    page = client.get("/signup").get_data(as_text=True)
    assert 'href="/login"' in page and "Continue with Google" in page and "Create account" in page


def test_cli_approve(tmp_path: Path) -> None:
    store = Database(tmp_path / "t.db")
    store.create_app_user(EMAIL, None)
    store.create_app_user(OTHER, None)
    runner = CliRunner()
    assert OTHER in runner.invoke(cli_app, ["auth", "list", "--db", str(store.path)]).output
    assert "pending" in runner.invoke(cli_app, ["auth", "list", "--db", str(store.path)]).output
    assert runner.invoke(cli_app, ["auth", "approve", OTHER, "--db", str(store.path)]).exit_code == 0
    assert runner.invoke(cli_app, ["auth", "approve", OTHER, "--db", str(store.path)]).exit_code == 1
    listing = runner.invoke(cli_app, ["auth", "list", "--db", str(store.path)]).output
    assert re.search(r"bob@example.com\s+active", listing)
