"""Sign-in (Google and password), CSRF, the YAML editor, and removing connectors."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from flask.testing import FlaskClient
from typer.testing import CliRunner

from secintegrate.cli import app as cli_app
from secintegrate.config.validator import has_errors, validate_text
from secintegrate.connector_files import template_text
from secintegrate.storage.db import Database
from secintegrate.web.app import create_app
from secintegrate.web.auth import LoginThrottle, hash_password, safe_next, verify_password
from secintegrate.web.google import GoogleCredentials
from secintegrate.web.options import ConnectorHooks, WebOptions

PASSWORD = "correct horse battery"
EMAIL = "ann@example.com"
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
GOOD_YAML = """# my own comment
connector: yaml_demo
source: demo
schedule: "0 * * * *"
base_url: https://example.com
auth: {type: none}
probe: {path: /ping}
endpoints:
  - name: e
    path: /x
    mapping:
      target: event
      fields:
        id: {from: id, required: true}
        timestamp: {from: ts, required: true}
        severity: {from: sev, default: unknown}
"""


class Google:
    """A stand-in for Google's token and userinfo endpoints."""

    def __init__(self) -> None:
        self.email = EMAIL
        self.verified = True
        self.token_ok = True
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/token":
            return httpx.Response(200 if self.token_ok else 400, json={"access_token": "at-fake"})
        return httpx.Response(200, json={"email": self.email, "email_verified": self.verified})


@pytest.fixture
def google() -> Google:
    return Google()


def make_client(tmp_path: Path, db: Database, google: Google | None = None, hooks: ConnectorHooks | None = None,
                login: bool = True) -> FlaskClient:
    options = WebOptions(
        require_login=login, session_secret="s" * 32, hooks=hooks,
        google=lambda: GoogleCredentials("client-id-1", "client-secret-1"),
        transport=httpx.MockTransport((google or Google()).handle),
    )
    return create_app(tmp_path / "cfg", db, lambda: {"MY_API_KEY"}, options).test_client()


def token(client: FlaskClient) -> str:
    match = CSRF.search(client.get("/login").get_data(as_text=True))
    assert match is not None
    return match.group(1)


def sign_in(client: FlaskClient, db: Database) -> str:
    db.set_app_password(EMAIL, hash_password(PASSWORD))
    csrf = token(client)
    response = client.post("/login", data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf})
    assert response.status_code == 302
    page = client.get("/").get_data(as_text=True)
    match = CSRF.search(page)
    assert match is not None
    return match.group(1)


# --- password hashing and helpers ---------------------------------------------------------------
def test_password_hash_verifies_and_is_salted() -> None:
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second and PASSWORD not in first
    assert verify_password(PASSWORD, first) and not verify_password("wrong", first)
    assert not verify_password(PASSWORD, "garbage") and not verify_password(PASSWORD, "md5$1$2$3$ab$cd")


def test_next_redirects_stay_on_site() -> None:
    assert safe_next("/connectors/new") == "/connectors/new"
    for bad in ("//evil.com", "https://evil.com", "/\\evil.com", "", None):
        assert safe_next(bad) == "/"


def test_throttle_blocks_then_expires() -> None:
    now = [0.0]
    throttle = LoginThrottle(max_failures=2, window_seconds=10, clock=lambda: now[0])
    throttle.fail("k")
    assert not throttle.blocked("k")
    throttle.fail("k")
    assert throttle.blocked("k")
    now[0] = 11.0
    assert not throttle.blocked("k")


# --- the login wall -----------------------------------------------------------------------------
def test_anonymous_visitors_are_sent_to_login(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert client.get("/").headers["Location"].startswith("/login")
    assert client.get("/connectors/new").status_code == 302
    assert client.post("/connectors/validate-yaml", data={"yaml_text": "x"}).status_code in (400, 401)
    assert client.get("/login").status_code == 200


def test_password_login_works_and_shows_the_user(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    sign_in(client, db)
    page = client.get("/").get_data(as_text=True)
    assert EMAIL in page and "Sign out" in page


def test_wrong_password_and_unknown_email_look_the_same(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    db.set_app_password(EMAIL, hash_password(PASSWORD))
    csrf = token(client)
    wrong = client.post("/login", data={"email": EMAIL, "password": "nope", "csrf_token": csrf})
    unknown = client.post("/login", data={"email": "nobody@example.com", "password": "nope", "csrf_token": csrf})
    assert wrong.status_code == unknown.status_code == 401
    assert "Wrong email or password." in wrong.get_data(as_text=True)
    assert "Wrong email or password." in unknown.get_data(as_text=True)


def test_repeated_failures_lock_out_even_the_right_password(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    db.set_app_password(EMAIL, hash_password(PASSWORD))
    csrf = token(client)
    for _ in range(5):
        client.post("/login", data={"email": EMAIL, "password": "nope", "csrf_token": csrf})
    locked = client.post("/login", data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf})
    assert locked.status_code == 429


def test_posts_without_a_csrf_token_are_rejected(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    db.set_app_password(EMAIL, hash_password(PASSWORD))
    assert client.post("/login", data={"email": EMAIL, "password": PASSWORD}).status_code == 400
    sign_in(client, db)
    assert client.post("/connectors/anything/delete").status_code == 400
    assert client.post("/logout").status_code == 400


def test_logout_ends_the_session(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    csrf = sign_in(client, db)
    assert client.post("/logout", data={"csrf_token": csrf}).status_code == 302
    assert client.get("/").status_code == 302


def test_login_ignores_offsite_next(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    db.set_app_password(EMAIL, hash_password(PASSWORD))
    csrf = token(client)
    response = client.post("/login?next=//evil.com",
                           data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf})
    assert response.headers["Location"] == "/"


def test_cookie_and_response_headers_are_hardened(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    response = client.get("/login")
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert response.headers["X-Frame-Options"] == "DENY" and response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


# --- Google ---------------------------------------------------------------------------------------
def start_google(client: FlaskClient) -> str:
    response = client.get("/auth/google")
    assert response.status_code == 302
    return str(response.headers["Location"])


def test_google_start_sends_pkce_and_state_but_never_the_secret(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    location = start_google(client)
    query = parse_qs(urlparse(location).query)
    assert urlparse(location).netloc == "accounts.google.com"
    assert query["client_id"] == ["client-id-1"] and query["code_challenge_method"] == ["S256"]
    assert query["state"][0] and query["code_challenge"][0] and "client-secret-1" not in location
    assert query["redirect_uri"] == ["http://localhost/auth/callback"]


def test_google_sign_in_for_an_allowed_address(tmp_path: Path, db: Database, google: Google) -> None:
    client = make_client(tmp_path, db, google)
    db.add_app_user(EMAIL)
    state = parse_qs(urlparse(start_google(client)).query)["state"][0]
    response = client.get(f"/auth/callback?state={state}&code=abc")
    assert response.status_code == 302 and response.headers["Location"] == "/"
    assert EMAIL in client.get("/").get_data(as_text=True)
    sent = google.requests[0].content.decode()
    assert "code_verifier=" in sent and "code=abc" in sent  # PKCE verifier went to Google, server to server


@pytest.mark.parametrize(("change", "expected"), [
    ({"email": "stranger@example.com"}, "pending"),
    ({"verified": False}, "unverified"),
    ({"token_ok": False}, "failed"),
])
def test_google_rejections(tmp_path: Path, db: Database, google: Google, change: dict[str, object],
                           expected: str) -> None:
    client = make_client(tmp_path, db, google)
    db.add_app_user(EMAIL)
    for key, value in change.items():
        setattr(google, key, value)
    state = parse_qs(urlparse(start_google(client)).query)["state"][0]
    response = client.get(f"/auth/callback?state={state}&code=abc")
    assert response.headers["Location"] == f"/login?error={expected}"
    assert client.get("/").status_code == 302  # still signed out


def test_google_callback_rejects_a_bad_or_missing_state(tmp_path: Path, db: Database, google: Google) -> None:
    client = make_client(tmp_path, db, google)
    db.add_app_user(EMAIL)
    start_google(client)
    assert client.get("/auth/callback?state=forged&code=abc").headers["Location"] == "/login?error=state"
    assert client.get("/auth/callback?state=x&code=abc").headers["Location"] == "/login?error=state"  # no pending
    start_google(client)
    assert client.get("/auth/callback?error=access_denied").headers["Location"] == "/login?error=denied"
    assert not google.requests  # Google was never asked


def test_login_page_explains_missing_google_setup(tmp_path: Path, db: Database) -> None:
    options = WebOptions(require_login=True, session_secret="s" * 32)
    client = create_app(tmp_path / "cfg", db, None, options).test_client()
    page = client.get("/login").get_data(as_text=True)
    assert "Google sign-in is not set up" in page and "GOOGLE_CLIENT_ID" in page
    assert client.get("/auth/google").headers["Location"] == "/login"
    assert "Sign in with Google" not in page


# --- YAML editor ----------------------------------------------------------------------------------
def test_template_is_valid_once_its_secret_exists() -> None:
    _, issues = validate_text(template_text(), "template.yaml", known_secrets={"MY_API_KEY"})
    assert not has_errors(issues) and issues == []
    _, missing = validate_text(template_text(), "template.yaml", known_secrets=set())
    assert any("Secret `MY_API_KEY` is not stored" in i.message for i in missing)


def test_yaml_editor_creates_a_file_and_keeps_comments(tmp_path: Path, db: Database) -> None:
    added: list[str] = []
    hooks = ConnectorHooks(added=lambda cfg: added.append(cfg.connector), removed=lambda c: None)
    client = make_client(tmp_path, db, hooks=hooks, login=False)
    response = client.post("/connectors/new-yaml", data={"yaml_text": GOOD_YAML})
    assert response.status_code == 200
    saved = (tmp_path / "cfg" / "yaml_demo.yaml").read_text(encoding="utf-8")
    assert saved == GOOD_YAML and "# my own comment" in saved
    assert added == ["yaml_demo"]  # the running scheduler was told


def test_yaml_editor_shows_line_numbers_and_writes_nothing_on_error(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, login=False)
    broken = GOOD_YAML.replace("path: /x", "path: x")
    response = client.post("/connectors/new-yaml", data={"yaml_text": broken})
    page = response.get_data(as_text=True)
    assert response.status_code == 400 and "line 10" in page and "Path must start with /." in page
    assert not (tmp_path / "cfg" / "yaml_demo.yaml").exists()
    checked = client.post("/connectors/validate-yaml", data={"yaml_text": broken}).get_json()
    assert checked["issues"][0]["line"] == 10 and checked["issues"][0]["severity"] == "error"


def test_yaml_editor_page_shows_the_template_and_both_tabs(tmp_path: Path, db: Database) -> None:
    page = make_client(tmp_path, db, login=False).get("/connectors/new?tab=yaml").get_data(as_text=True)
    assert "Hermes connector template" in page and "Use the form" in page and "Write YAML" in page


def test_yaml_editor_refuses_huge_input(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, login=False)
    assert client.post("/connectors/new-yaml", data={"yaml_text": "a" * 70_000}).status_code == 413


# --- removing connectors ----------------------------------------------------------------------------
def test_remove_moves_the_config_to_trash_and_clears_state(tmp_path: Path, db: Database) -> None:
    removed: list[str] = []
    hooks = ConnectorHooks(added=lambda cfg: None, removed=removed.append)
    client = make_client(tmp_path, db, hooks=hooks, login=False)
    client.post("/connectors/new-yaml", data={"yaml_text": GOOD_YAML})
    db.upsert("event", "demo", [{"id": "E1", "type": "t", "severity": "low", "timestamp": "2026-01-01T00:00:00Z",
                                 "description": ""}], "2026-10-31T00:00:00Z")
    db.add_probe("yaml_demo", True, None, 200, 5)
    db.set_cursor("yaml_demo", "e", "2026-01-01T00:00:00Z")
    response = client.post("/connectors/yaml_demo/delete")
    assert response.status_code == 302
    assert not (tmp_path / "cfg" / "yaml_demo.yaml").exists()
    assert len(list((tmp_path / "cfg" / ".trash").glob("yaml_demo-*.yaml"))) == 1  # recoverable
    assert db.get_connection("yaml_demo") is None and db.latest_probe("yaml_demo") is None
    assert db.get_cursor("yaml_demo", "e") is None and db.count("events") == 1  # records are kept
    assert removed == ["yaml_demo"]
    assert "yaml_demo" not in client.get("/").get_data(as_text=True)


def test_remove_rejects_unknown_and_odd_ids(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, login=False)
    assert client.post("/connectors/nothing_here/delete").status_code == 404
    assert client.post("/connectors/..%2Fsecrets/delete").status_code == 404
    assert client.post("/connectors/UPPER/delete").status_code == 404


def test_home_page_offers_a_remove_button(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db, login=False)
    client.post("/connectors/new-yaml", data={"yaml_text": GOOD_YAML})
    page = client.get("/").get_data(as_text=True)
    assert 'action="/connectors/yaml_demo/delete"' in page and "Remove" in page


# --- CLI ----------------------------------------------------------------------------------------------
def test_cli_template_and_remove(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    runner = CliRunner()
    shown = runner.invoke(cli_app, ["template"])
    assert shown.exit_code == 0 and "Hermes connector template" in shown.output
    out = tmp_path / "mine.yaml"
    assert runner.invoke(cli_app, ["template", "--out", str(out)]).exit_code == 0 and out.exists()
    assert runner.invoke(cli_app, ["template", "--out", str(out)]).exit_code == 1  # never overwrites
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "yaml_demo.yaml").write_text(GOOD_YAML, encoding="utf-8")
    db = str(tmp_path / "t.db")
    done = runner.invoke(cli_app, ["remove", "yaml_demo", "--yes", "-c", str(cfg), "--db", db])
    assert done.exit_code == 0 and not (cfg / "yaml_demo.yaml").exists()
    assert runner.invoke(cli_app, ["remove", "yaml_demo", "--yes", "-c", str(cfg), "--db", db]).exit_code == 2


def test_cli_auth_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = str(tmp_path / "t.db")
    runner = CliRunner()
    assert runner.invoke(cli_app, ["auth", "add", "not-an-email", "--db", db]).exit_code == 1
    assert runner.invoke(cli_app, ["auth", "add", "Ann@Example.com", "--db", db]).exit_code == 0
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr("secintegrate.cli_auth.getpass.getpass", lambda prompt="": next(answers))
    done = runner.invoke(cli_app, ["auth", "set-password", EMAIL, "--db", db])
    assert done.exit_code == 0 and PASSWORD not in done.output
    listing = runner.invoke(cli_app, ["auth", "list", "--db", db]).output
    assert EMAIL in listing and "google + password" in listing and PASSWORD not in listing
    short = iter(["short", "short"])
    monkeypatch.setattr("secintegrate.cli_auth.getpass.getpass", lambda prompt="": next(short))
    assert runner.invoke(cli_app, ["auth", "set-password", EMAIL, "--db", db]).exit_code == 1
    assert runner.invoke(cli_app, ["auth", "remove", EMAIL, "--db", db]).exit_code == 0
    assert runner.invoke(cli_app, ["auth", "remove", EMAIL, "--db", db]).exit_code == 1
    assert Database(db).get_app_user(EMAIL) is None


def test_db_reset_keeps_sign_in_users_and_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    db = tmp_path / "t.db"
    store = Database(db)
    store.add_app_user(EMAIL)
    runner = CliRunner()
    assert runner.invoke(cli_app, ["db", "reset", "--yes", "--db", str(db)]).exit_code == 0
    assert store.get_app_user(EMAIL) is not None
