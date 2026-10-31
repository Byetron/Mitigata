"""Each account has its own connectors, data, health history and keys."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from flask.testing import FlaskClient
from typer.testing import CliRunner

from conftest import RecordingNotifier, make_cfg
from secintegrate.bootstrap import App
from secintegrate.cli import app as cli_app
from secintegrate.config.validator import has_errors, validate_text
from secintegrate.scheduler import HermesScheduler, _retry_id, schedule_first_runs
from secintegrate.security.errors import SecretNotFoundError
from secintegrate.security.keybackends import InMemoryKeyBackend
from secintegrate.storage.db import Database
from secintegrate.web.app import create_app
from secintegrate.web.auth import hash_password
from secintegrate.web.options import ConnectorHooks, WebOptions
from secintegrate.workspaces import WorkspaceManager, user_slug

ANN = "ann@example.com"  # the first account, so she keeps the connectors that came with Hermes
BOB = "bob@example.com"
PASSWORD = "correct horse battery"
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def connector_yaml(name: str, source: str = "demo", base_url: str = "https://example.com",
                   secret: str | None = None) -> str:
    auth = f"{{type: bearer, secret: {secret}}}" if secret else "{type: none}"
    return (f"connector: {name}\nsource: {source}\nschedule: '0 * * * *'\nbase_url: {base_url}\nauth: {auth}\n"
            "probe: {path: /ping}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
            "      fields:\n        id: {from: id, required: true}\n        timestamp: {from: ts, required: true}\n"
            "        severity: {from: sev, default: unknown}\n")


def add_accounts(db: Database) -> None:
    for email, day in ((ANN, "01"), (BOB, "02")):
        db.create_app_user(email, hash_password(PASSWORD))
        with db.conn() as c:
            c.execute("UPDATE app_users SET added_at=? WHERE email=?", (f"2026-01-{day}T00:00:00Z", email))


def build_manager(tmp_path: Path, db: Database) -> WorkspaceManager:
    legacy = tmp_path / "legacy_connectors"
    legacy.mkdir(exist_ok=True)
    return WorkspaceManager(db, legacy, db.path, backend=InMemoryKeyBackend(), notifier=RecordingNotifier())


def web(manager: WorkspaceManager, db: Database, hooks: ConnectorHooks | None = None) -> FlaskClient:
    options = WebOptions(require_login=True, session_secret="s" * 32, hooks=hooks,
                         workspaces=manager.web_context)
    default = manager.workspace(ANN)
    return create_app(default.config_dir, db, None, options).test_client()


def sign_in(client: FlaskClient, email: str) -> str:
    page = client.get("/login").get_data(as_text=True)
    match = CSRF.search(page)
    assert match is not None
    client.post("/login", data={"email": email, "password": PASSWORD, "csrf_token": match.group(1)})
    home = CSRF.search(client.get("/").get_data(as_text=True))
    assert home is not None
    return home.group(1)


# --- who owns what ----------------------------------------------------------------------------------------------
def test_folder_names_are_safe_whatever_the_email_contains() -> None:
    for email in ("../../Windows/system32@x.y", "a b@c.d", "UPPER@Case.IO"):
        slug = user_slug(email)
        assert re.fullmatch(r"[0-9a-f]{20}", slug)
    assert user_slug("Ann@Example.com") == user_slug(" ann@example.com ")  # the same person, the same folder
    assert user_slug(ANN) != user_slug(BOB)


def test_the_first_account_keeps_the_original_connectors(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    assert manager.legacy_owner() == ANN
    ann, bob = manager.workspace(ANN), manager.workspace(BOB)
    assert ann.legacy and ann.config_dir == tmp_path / "legacy_connectors" and ann.db_path == db.path
    assert not bob.legacy and bob.config_dir.is_dir()
    assert bob.config_dir != ann.config_dir and bob.db_path != ann.db_path
    assert bob.config_dir.parent.parent == db.path.parent / "workspaces"  # next to the main database


def test_later_accounts_do_not_take_over_and_nobody_inherits_silently(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    assert manager.legacy_owner() == ANN
    db.create_app_user("cat@example.com", None)
    assert manager.legacy_owner() == ANN  # a newcomer never becomes the owner
    db.remove_app_user(ANN)
    assert manager.legacy_owner() is None and not manager.is_legacy(BOB)  # Bob does not inherit Ann's keys


def test_no_accounts_means_no_owner(tmp_path: Path, db: Database) -> None:
    assert build_manager(tmp_path, db).legacy_owner() is None


# --- isolation -------------------------------------------------------------------------------------------------------
def test_each_account_has_its_own_keys(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    manager.app_for(ANN).vault.store("ANN_SECRET", "ann-fake-value-0000")
    assert "ANN_SECRET" in manager.app_for(ANN).vault.list_names()
    assert "ANN_SECRET" not in manager.app_for(BOB).vault.list_names()
    with pytest.raises(SecretNotFoundError):
        manager.app_for(BOB).vault.load("ANN_SECRET")


def test_a_new_account_starts_empty_and_cannot_see_anothers_data(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    (tmp_path / "legacy_connectors" / "ann_only.yaml").write_text(connector_yaml("ann_only", "asrc"), encoding="utf-8")
    db.upsert("event", "asrc", [{"id": "ANN-EVENT-1", "type": "t", "severity": "high",
                                "timestamp": "2026-10-01T00:00:00Z", "description": "private to ann"}],
              "2026-10-31T00:00:00Z")
    ann, bob = web(manager, db), web(manager, db)
    sign_in(ann, ANN)
    sign_in(bob, BOB)
    ann_page = ann.get("/").get_data(as_text=True)
    assert "ann_only" in ann_page and "ANN-EVENT-1" in ann_page
    bob_page = bob.get("/").get_data(as_text=True)
    assert "ann_only" not in bob_page and "ANN-EVENT-1" not in bob_page and "asrc" not in bob_page
    assert "You have no connectors yet" in bob_page and "Create your first connector" in bob_page


def test_connectors_are_created_in_the_creators_own_workspace(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    calls: list[tuple[str, str]] = []
    hooks = ConnectorHooks(added=lambda owner, cfg: calls.append((owner, cfg.connector)),
                           removed=lambda owner, name: calls.append((owner, f"removed {name}")))
    ann, bob = web(manager, db, hooks), web(manager, db, hooks)
    sign_in(ann, ANN)
    bob_token = sign_in(bob, BOB)
    saved = bob.post("/connectors/new-yaml", data={"yaml_text": connector_yaml("bob_only"), "csrf_token": bob_token})
    assert saved.status_code == 200
    assert (manager.workspace(BOB).config_dir / "bob_only.yaml").exists()
    assert not (manager.workspace(ANN).config_dir / "bob_only.yaml").exists()
    assert calls == [(BOB, "bob_only")]  # the running scheduler is told whose connector it is
    assert "bob_only" in bob.get("/").get_data(as_text=True)
    assert "bob_only" not in ann.get("/").get_data(as_text=True)


def test_one_account_cannot_remove_anothers_connector(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    target = tmp_path / "legacy_connectors" / "ann_only.yaml"
    target.write_text(connector_yaml("ann_only"), encoding="utf-8")
    bob = web(manager, db)
    token = sign_in(bob, BOB)
    assert bob.post("/connectors/ann_only/delete", data={"csrf_token": token}).status_code == 404
    assert target.exists()
    ann = web(manager, db)
    assert ann.post("/connectors/ann_only/delete", data={"csrf_token": sign_in(ann, ANN)}).status_code == 302
    assert not target.exists()


def test_another_accounts_key_cannot_be_used_in_a_connector(tmp_path: Path, db: Database) -> None:
    add_accounts(db)
    manager = build_manager(tmp_path, db)
    manager.app_for(ANN).vault.store("ANN_TOKEN", "ann-fake-value-0000")
    bob = web(manager, db)
    token = sign_in(bob, BOB)
    response = bob.post("/connectors/new-yaml",
                        data={"yaml_text": connector_yaml("steal", secret="ANN_TOKEN"), "csrf_token": token})
    assert response.status_code == 400 and "Secret `ANN_TOKEN` is not stored" in response.get_data(as_text=True)
    assert not list(manager.workspace(BOB).config_dir.glob("steal*"))


# --- connectors made in the web app cannot reach internal addresses ---------------------------------------------------
@pytest.mark.parametrize("base_url", ["https://127.0.0.1", "https://localhost", "https://10.0.0.5",
                                      "https://192.168.1.10", "https://169.254.169.254", "https://printer.local"])
def test_web_connectors_cannot_point_at_this_computer_or_a_private_network(
        tmp_path: Path, db: Database, base_url: str) -> None:
    add_accounts(db)
    bob = web(build_manager(tmp_path, db), db)
    token = sign_in(bob, BOB)
    response = bob.post("/connectors/new-yaml", data={"yaml_text": connector_yaml("probe_me", base_url=base_url),
                                                      "csrf_token": token})
    assert response.status_code == 400 and "public address" in response.get_data(as_text=True)
    ok = bob.post("/connectors/new-yaml", data={"yaml_text": connector_yaml("fine", base_url="https://api.example.com"),
                                                "csrf_token": token})
    assert ok.status_code == 200


def test_the_command_line_still_allows_internal_addresses_for_the_administrator() -> None:
    text = connector_yaml("local_one", base_url="https://127.0.0.1")
    assert not has_errors(validate_text(text, "t.yaml")[1])
    assert has_errors(validate_text(text, "t.yaml", allow_internal=False)[1])


# --- the scheduler keeps accounts apart ------------------------------------------------------------------
def test_scheduler_jobs_of_two_accounts_never_collide(db: Database, vault: object, notifier: RecordingNotifier) -> None:
    app = App(config_dir=Path("."), db=db, vault=vault, notifier=notifier)  # type: ignore[arg-type]
    cfg = make_cfg("https://example.com", probe={"path": "/ping"})
    sched = HermesScheduler()
    sched.add_connector(cfg, app)  # the original workspace (empty owner)
    sched.add_connector(cfg, app, BOB)  # the same connector name for another account
    assert sched.get_job("github_advisories") and sched.get_job(f"{BOB}|github_advisories")
    assert sched.get_job(f"{BOB}|github_advisories__probe")
    schedule_first_runs(sched, [cfg], app, BOB)
    assert sched.get_job(f"{BOB}|github_advisories__first") and _retry_id("c", "o") == "o|c__retry"
    sched.remove_connector("github_advisories", BOB)
    assert not sched.get_job(f"{BOB}|github_advisories") and not sched.get_job(f"{BOB}|github_advisories__probe")
    assert sched.get_job("github_advisories")  # the other account's job is untouched


# --- command line ----------------------------------------------------------------------------------------
def test_user_option_works_on_that_accounts_own_keys(tmp_path: Path, db: Database,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    add_accounts(db)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setattr("secintegrate.cli_secrets.getpass.getpass", lambda prompt="": "  fake-value-0000 ")
    runner = CliRunner()
    base = ["--db", str(db.path), "-c", str(cfg)]
    assert runner.invoke(cli_app, ["secret", "set", "BOB_KEY", "--user", BOB, *base]).exit_code == 0
    assert runner.invoke(cli_app, ["secret", "set", "ANN_KEY", "--user", ANN, *base]).exit_code == 0
    bob_list = runner.invoke(cli_app, ["secret", "list", "--user", BOB, *base]).output
    ann_list = runner.invoke(cli_app, ["secret", "list", "--user", ANN, *base]).output
    assert "BOB_KEY" in bob_list and "ANN_KEY" not in bob_list
    assert "ANN_KEY" in ann_list and "BOB_KEY" not in ann_list
    manager = WorkspaceManager(db, cfg, db.path)
    assert manager.app_for(BOB).vault.load("BOB_KEY").reveal() == "fake-value-0000"  # stray spaces were trimmed


def test_user_option_rejects_an_unknown_account(tmp_path: Path, db: Database,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    result = CliRunner().invoke(cli_app, ["secret", "list", "--user", "ghost@example.com", "--db", str(db.path),
                                          "-c", str(tmp_path)])
    assert result.exit_code == 2 and "no account" in result.output.lower()
