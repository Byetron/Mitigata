"""Creating accounts: open sign-up with a captcha, Google first sign-in, host pinning. There is no approval step."""
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

from conftest import attempt
from secintegrate.cli import app as cli_app
from secintegrate.storage.db import Database
from secintegrate.web.app import create_app
from secintegrate.web.auth import hash_password
from secintegrate.web.google import GoogleCredentials
from secintegrate.web.options import WebOptions
from test_web_auth import CSRF, EMAIL, PASSWORD, Google, start_google

OTHER = "bob@example.com"
QUESTION = re.compile(r"What is (\d+) (plus|minus) (\d+)\?")


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


def answer_for(page: str) -> str:
    match = QUESTION.search(page)
    assert match is not None, "the sign-up page has no captcha question"
    a, word, b = int(match[1]), match[2], int(match[3])
    return str(a + b if word == "plus" else a - b)


def sign_up(client: FlaskClient, email: str, password: str = PASSWORD, confirm: str | None = None,
            answer: str | None = None, **extra: str) -> TestResponse:
    page = client.get("/signup").get_data(as_text=True)
    match = CSRF.search(page)
    assert match is not None
    data = {"email": email, "password": password, "confirm": password if confirm is None else confirm,
            "captcha": answer_for(page) if answer is None else answer, "csrf_token": match.group(1), **extra}
    return client.post("/signup", data=data)


def csrf_from(client: FlaskClient, path: str) -> str:
    match = CSRF.search(client.get(path).get_data(as_text=True))
    assert match is not None
    return match.group(1)


# --- database --------------------------------------------------------------------------------------------
def test_new_accounts_are_created_at_once_and_never_overwritten(db: Database) -> None:
    assert db.create_app_user(EMAIL, hash_password(PASSWORD)) == "created"
    first = db.get_app_user(EMAIL)
    assert db.create_app_user(EMAIL, hash_password("another password")) == "exists"
    assert db.get_app_user(EMAIL) == first and len(db.list_app_users()) == 1


def test_old_databases_are_upgraded_and_waiting_accounts_let_in(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE app_users (email TEXT PRIMARY KEY, password_hash TEXT, added_at TEXT NOT NULL, "
                "status TEXT NOT NULL DEFAULT 'active')")
    old.execute("INSERT INTO app_users VALUES ('ann@example.com', NULL, '2026-01-01T00:00:00Z', 'active')")
    old.execute("INSERT INTO app_users VALUES ('wait@example.com', NULL, '2026-01-02T00:00:00Z', 'pending')")
    old.commit()
    old.close()
    upgraded = Database(path)
    assert {u["email"] for u in upgraded.list_app_users()} == {"ann@example.com", "wait@example.com"}
    waiting = upgraded.get_app_user("wait@example.com")
    assert waiting is not None and waiting["status"] == "active"  # approval no longer exists, so nobody is stuck


def test_settings_are_stored(db: Database) -> None:
    assert db.get_setting("k") is None
    db.set_setting("k", "one")
    db.set_setting("k", "two")
    assert db.get_setting("k") == "two"


# --- sign-up with a captcha ----------------------------------------------------------------------------------
def test_every_signup_gets_in_straight_away(tmp_path: Path, db: Database) -> None:
    first, second = make_client(tmp_path, db), make_client(tmp_path, db)
    assert sign_up(first, EMAIL).status_code == 302
    assert sign_up(second, OTHER).status_code == 302  # the second account does not wait for anyone
    assert EMAIL in first.get("/").get_data(as_text=True) and OTHER in second.get("/").get_data(as_text=True)
    assert PASSWORD not in str(db.get_app_user(OTHER))  # only a hash is stored


def test_a_wrong_answer_creates_nothing_and_asks_a_new_question(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    response = sign_up(client, EMAIL, answer="999")
    page = response.get_data(as_text=True)
    assert response.status_code == 400 and "That answer is not right" in page and QUESTION.search(page)
    assert db.list_app_users() == []


def test_posting_without_ever_seeing_a_question_is_refused(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    with client.session_transaction() as session:
        session["csrf"] = "fixed-token"  # a valid session and CSRF token, but no captcha question was ever issued
    response = client.post("/signup", data={"email": EMAIL, "password": PASSWORD, "confirm": PASSWORD,
                                            "captcha": "5", "csrf_token": "fixed-token"})
    assert response.status_code == 400 and db.list_app_users() == []


def test_the_answer_is_not_kept_in_the_clear_and_each_question_is_single_use(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    client.get("/signup")
    with client.session_transaction() as session:
        first = dict(session["captcha"])
    assert set(first) == {"nonce", "mac", "at"}  # a keyed hash, never the answer itself
    sign_up(client, EMAIL, "short", "short")  # fails on the password, but the question is used up either way
    with client.session_transaction() as session:
        assert session["captcha"]["nonce"] != first["nonce"]


def test_an_old_question_expires(tmp_path: Path, db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    client = make_client(tmp_path, db)
    page = client.get("/signup").get_data(as_text=True)
    token = CSRF.search(page)
    assert token is not None
    real = time.time
    monkeypatch.setattr("secintegrate.web.auth.time.time", lambda: real() + 700)
    response = client.post("/signup", data={"email": EMAIL, "password": PASSWORD, "confirm": PASSWORD,
                                            "captcha": answer_for(page), "csrf_token": token.group(1)})
    assert response.status_code == 400 and db.list_app_users() == []


def test_the_hidden_trap_field_catches_programs(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    response = sign_up(client, EMAIL, website="http://spam.example")
    assert response.status_code == 400 and db.list_app_users() == []


def test_an_existing_email_is_told_to_sign_in_and_is_not_changed(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    before = db.get_app_user(EMAIL)
    client = make_client(tmp_path, db)
    response = sign_up(client, EMAIL, "attacker chosen password")
    assert response.status_code == 409 and "already has an account" in response.get_data(as_text=True)
    assert db.get_app_user(EMAIL) == before
    ok = attempt(make_client(tmp_path, db), EMAIL, PASSWORD)
    assert ok.status_code == 302


@pytest.mark.parametrize(("email", "password", "confirm", "message"), [
    ("not-an-email", PASSWORD, PASSWORD, "valid email"),
    (OTHER, "short", "short", "at least 10"),
    (OTHER, PASSWORD, "different password", "do not match"),
])
def test_signup_validation(tmp_path: Path, db: Database, email: str, password: str, confirm: str,
                           message: str) -> None:
    response = sign_up(make_client(tmp_path, db), email, password, confirm)
    assert response.status_code == 400 and message in response.get_data(as_text=True)
    assert db.list_app_users() == []


def test_signup_is_throttled_and_needs_a_csrf_token(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert client.post("/signup", data={"email": OTHER, "password": PASSWORD, "confirm": PASSWORD}).status_code == 400
    for i in range(5):
        sign_up(client, f"user{i}@example.com", "short", "short")
    assert sign_up(client, OTHER).status_code == 429


def test_the_pages_never_mention_approval(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    for path in ("/login", "/signup"):
        assert "approv" not in client.get(path).get_data(as_text=True).lower()
    page = client.get("/signup").get_data(as_text=True)
    assert 'name="captcha"' in page and 'name="website"' in page and 'href="/login"' in page
    assert "Continue with Google" in page and "starts empty" in page


# --- Google creating an account ---------------------------------------------------------------------------------
def google_sign_in(client: FlaskClient, email: str, google: Google) -> str:
    google.email = email
    state = parse_qs(urlparse(start_google(client)).query)["state"][0]
    return str(client.get(f"/auth/callback?state={state}&code=abc").headers["Location"])


def test_a_first_google_sign_in_creates_an_account_with_no_approval(tmp_path: Path, db: Database,
                                                                    google: Google) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))  # someone already has an account
    client = make_client(tmp_path, db, google)
    assert google_sign_in(client, OTHER, google) == "/"
    user = db.get_app_user(OTHER)
    assert user is not None and user["password_hash"] is None
    assert OTHER in client.get("/").get_data(as_text=True)


def test_google_sign_in_leaves_an_existing_account_alone(tmp_path: Path, db: Database, google: Google) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    before = db.get_app_user(EMAIL)
    assert google_sign_in(make_client(tmp_path, db, google), EMAIL, google) == "/"
    assert db.get_app_user(EMAIL) == before  # still has its password


# --- there is no user section and nothing to approve ------------------------------------------------------------
def signed_in(tmp_path: Path, db: Database, email: str) -> FlaskClient:
    client = make_client(tmp_path, db)
    attempt(client, email, PASSWORD)
    return client


def test_there_is_no_users_page(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    admin = signed_in(tmp_path, db, EMAIL)
    assert 'href="/users"' not in admin.get("/").get_data(as_text=True)
    assert admin.get("/users").status_code == 404
    assert make_client(tmp_path, db).get("/users").status_code == 302  # signed out: sent to sign in


def test_removing_a_user_signs_them_out_at_once(tmp_path: Path, db: Database) -> None:
    db.create_app_user(EMAIL, hash_password(PASSWORD))
    db.create_app_user(OTHER, hash_password(PASSWORD))
    guest = signed_in(tmp_path, db, OTHER)
    assert guest.get("/").status_code == 200
    removed = CliRunner().invoke(cli_app, ["auth", "remove", OTHER, "--db", str(db.path)])
    assert removed.exit_code == 0 and "stay on disk" in removed.output
    assert guest.get("/").status_code == 302  # the session no longer works


# --- pinning the address Google redirects to ---------------------------------------------------------------------
def test_other_host_names_are_sent_to_the_canonical_address(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, public_url="http://127.0.0.1:8000")
    moved = client.get("/connectors/new?tab=yaml", headers={"Host": "localhost:8000"})
    assert moved.status_code == 302 and moved.headers["Location"] == "http://127.0.0.1:8000/connectors/new?tab=yaml"
    assert client.get("/login", headers={"Host": "127.0.0.1:8000"}).status_code == 200


def test_google_redirect_uri_ignores_the_host_header(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, public_url="http://127.0.0.1:8000")
    location = start_google(client, headers={"Host": "127.0.0.1:8000", "X-Forwarded-Host": "evil.example"})
    query = parse_qs(urlparse(location).query)
    assert query["redirect_uri"] == ["http://127.0.0.1:8000/auth/callback"]


# --- command line --------------------------------------------------------------------------------------------------
def test_cli_has_no_approve_command_and_lists_accounts(tmp_path: Path) -> None:
    store = Database(tmp_path / "t.db")
    store.create_app_user(EMAIL, None)
    store.create_app_user(OTHER, hash_password(PASSWORD))
    runner = CliRunner()
    assert runner.invoke(cli_app, ["auth", "approve", OTHER, "--db", str(store.path)]).exit_code == 2  # no such command
    listing = runner.invoke(cli_app, ["auth", "list", "--db", str(store.path)]).output
    assert EMAIL in listing and OTHER in listing and "pending" not in listing and "google only" in listing
