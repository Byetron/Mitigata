"""Records follow their connector: removing a connector deletes what it fetched, adding one fetches its data."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pytest_httpserver import HTTPServer
from typer.testing import CliRunner

from conftest import RecordingNotifier, advisory, make_cfg
from secintegrate.autoheal import reprocess_quarantine
from secintegrate.bootstrap import App
from secintegrate.cli import app as cli_app
from secintegrate.connector_files import remove_connector
from secintegrate.runner import run_connector
from secintegrate.scheduler import ADDED_RUN_DELAY_SECONDS, HermesScheduler, _run_job
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database
from secintegrate.web.app import create_app
from secintegrate.web.options import ConnectorHooks, WebOptions
from test_web_auth import GOOD_YAML


def event(i: str) -> dict[str, str]:
    return {"id": i, "type": "t", "severity": "high", "timestamp": "2026-10-01T00:00:00Z", "description": "d"}


def connector_yaml(name: str, source: str) -> str:
    return (f"connector: {name}\nsource: {source}\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
            "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
            "      fields:\n        id: {from: id, required: true}\n        timestamp: {from: ts, required: true}\n"
            "        severity: {from: sev, default: unknown}\n")


def sources(db: Database) -> list[str]:
    return [s["source"] for s in db.dashboard()["event_sources"]]


# --- records remember their connector ---------------------------------------------------------------------------
def test_records_are_tagged_with_the_connector_that_fetched_them(db: Database) -> None:
    db.upsert("event", "s", [event("A")], "2026-10-31T00:00:00Z", "alpha")
    db.upsert("event", "s", [event("A")], "2026-10-31T00:00:00Z", "beta")  # the same record, fetched again by another
    with db.conn() as c:
        assert c.execute("SELECT connector FROM events WHERE id='A'").fetchone()[0] == "beta"


def test_old_databases_gain_the_connector_column(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    for table, cols in (("users", "name TEXT, email TEXT, status TEXT, last_login TEXT"),
                        ("devices", "hostname TEXT, ip TEXT, os TEXT, owner TEXT, last_seen TEXT"),
                        ("events", "type TEXT, severity TEXT, timestamp TEXT, description TEXT")):
        old.execute(f"CREATE TABLE {table} (source TEXT NOT NULL, id TEXT NOT NULL, {cols}, "
                    "fetched_at TEXT NOT NULL, PRIMARY KEY (source, id))")
    old.execute("INSERT INTO events (source, id, fetched_at) VALUES ('s', 'OLD', '2026-01-01T00:00:00Z')")
    old.commit()
    old.close()
    upgraded = Database(path)
    with upgraded.conn() as c:
        for table in ("users", "devices", "events"):
            assert "connector" in {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        assert c.execute("SELECT connector FROM events WHERE id='OLD'").fetchone()[0] is None  # kept, untagged


def test_deleting_by_connector_only_touches_that_connector(db: Database) -> None:
    db.upsert("event", "s", [event("A"), event("B")], "2026-10-31T00:00:00Z", "alpha")
    db.upsert("event", "s", [event("C")], "2026-10-31T00:00:00Z", "beta")
    db.upsert("device", "s", [{"id": "D1", "hostname": "h", "ip": "1.1.1.1", "os": "x", "owner": "o",
                              "last_seen": "2026-01-01T00:00:00Z"}], "2026-10-31T00:00:00Z", "alpha")
    db.upsert("user", "s", [{"id": "U1", "name": "n", "email": "e", "status": "active", "last_login": None}],
              "2026-10-31T00:00:00Z", "alpha")
    assert db.delete_connector_data("alpha", "s", source_shared=True) == 4  # two events, a device and a user
    assert (db.count("events"), db.count("devices"), db.count("users")) == (1, 0, 0)


def test_old_untagged_rows_go_only_when_the_source_belongs_to_that_connector_alone(db: Database) -> None:
    db.upsert("event", "s", [event("OLD")], "2026-10-31T00:00:00Z", None)  # fetched before rows were tagged
    assert db.delete_connector_data("alpha", "s", source_shared=True) == 0  # another connector shares the label
    assert db.count("events") == 1
    assert db.delete_connector_data("alpha", "s", source_shared=False) == 1
    assert db.count("events") == 0


# --- removing a connector -------------------------------------------------------------------------------------------
def test_removing_a_connector_deletes_what_it_fetched_and_only_that(
        tmp_path: Path, db: Database, vault: SecretVault, notifier: RecordingNotifier, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), advisory(2)])
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    for name in ("alpha", "beta"):
        (config_dir / f"{name}.yaml").write_text(connector_yaml(name, f"src_{name}"), encoding="utf-8")
        cfg = make_cfg(httpserver.url_for(""), connector=name, source=f"src_{name}")
        assert run_connector(cfg, db, vault, notifier, sleep=lambda s: None).records_ok == 2
    assert db.count("events") == 4
    removal = remove_connector(config_dir, db, "alpha")
    assert removal is not None and removal.records == 2
    assert removal.config.parent == config_dir / ".trash" and removal.config.exists()
    assert db.count("events") == 2 and sources(db) == ["src_beta"]
    assert db.get_connection("alpha") is None and db.get_cursor("alpha", "advisories") is None


def test_a_label_shared_with_another_connector_keeps_the_other_ones_records(tmp_path: Path, db: Database) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    for name in ("alpha", "beta"):
        (config_dir / f"{name}.yaml").write_text(connector_yaml(name, "shared"), encoding="utf-8")
    db.upsert("event", "shared", [event("A1")], "2026-10-31T00:00:00Z", "alpha")
    db.upsert("event", "shared", [event("B1")], "2026-10-31T00:00:00Z", "beta")
    db.upsert("event", "shared", [event("OLD")], "2026-10-31T00:00:00Z", None)
    first = remove_connector(config_dir, db, "alpha")
    assert first is not None and first.records == 1  # only alpha's own record
    assert db.count("events") == 2  # beta's record and the untagged one stay: beta may own it
    second = remove_connector(config_dir, db, "beta")
    assert second is not None and second.records == 2
    assert db.count("events") == 0


def test_the_home_page_forgets_a_removed_connectors_events(tmp_path: Path, db: Database) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "alpha.yaml").write_text(connector_yaml("alpha", "asrc"), encoding="utf-8")
    db.upsert("event", "asrc", [event("ASRC-EVENT-1")], "2026-10-31T00:00:00Z", "alpha")
    client = create_app(config_dir, db).test_client()
    before = client.get("/").get_data(as_text=True)
    assert "ASRC-EVENT-1" in before and "asrc" in before
    assert client.post("/connectors/alpha/delete").status_code == 302
    after = client.get("/").get_data(as_text=True)
    assert "ASRC-EVENT-1" not in after and "asrc" not in after
    assert "Delete" not in after and "every record it fetched" not in after  # nothing left to remove


def test_the_remove_button_warns_that_records_are_deleted(tmp_path: Path, db: Database) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "alpha.yaml").write_text(connector_yaml("alpha", "asrc"), encoding="utf-8")
    page = create_app(config_dir, db).test_client().get("/").get_data(as_text=True)
    assert "every record it fetched are deleted" in page and "Fetched records are kept" not in page


def test_removing_from_the_command_line_says_how_many_records_went(tmp_path: Path, db: Database,
                                                                   monkeypatch: object) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "alpha.yaml").write_text(connector_yaml("alpha", "asrc"), encoding="utf-8")
    db.upsert("event", "asrc", [event("A"), event("B")], "2026-10-31T00:00:00Z", "alpha")
    result = CliRunner().invoke(cli_app, ["remove", "alpha", "--yes", "-c", str(config_dir), "--db", str(db.path)],
                                env={"SECINTEGRATE_MASTER_KEY": "ab" * 32})
    assert result.exit_code == 0 and "deleted 2 fetched record(s)" in result.output
    assert db.count("events") == 0


def test_removing_and_adding_back_fetches_everything_again(
        tmp_path: Path, db: Database, vault: SecretVault, notifier: RecordingNotifier, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), advisory(2)])
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "alpha.yaml").write_text(connector_yaml("alpha", "src_alpha"), encoding="utf-8")
    cfg = make_cfg(httpserver.url_for(""), connector="alpha", source="src_alpha")
    run_connector(cfg, db, vault, notifier, sleep=lambda s: None)
    remove_connector(config_dir, db, "alpha")
    assert db.count("events") == 0
    again = run_connector(cfg, db, vault, notifier, sleep=lambda s: None)  # no old cursor is left to skip records
    assert again.records_ok == 2 and db.count("events") == 2


def test_records_set_free_from_quarantine_are_tagged_too(
        tmp_path: Path, db: Database, vault: SecretVault, notifier: RecordingNotifier, httpserver: HTTPServer) -> None:
    odd = advisory(2, alt_id="GHSA-FIXED")
    del odd["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), odd])
    run_connector(make_cfg(httpserver.url_for(""), connector="alpha"), db, vault, notifier, sleep=lambda s: None)
    fixed = make_cfg(httpserver.url_for(""), connector="alpha")
    fixed.endpoints[0].mapping.fields["id"].from_ = "alt_id"
    assert reprocess_quarantine(fixed, db) == 1
    with db.conn() as c:
        assert c.execute("SELECT connector FROM events WHERE id='GHSA-FIXED'").fetchone()[0] == "alpha"


# --- adding a connector ---------------------------------------------------------------------------------------
def test_adding_a_connector_fetches_its_valid_data_into_events(
        tmp_path: Path, db: Database, vault: SecretVault, notifier: RecordingNotifier, httpserver: HTTPServer) -> None:
    broken = advisory(3)
    del broken["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), advisory(2), broken])
    cfg = make_cfg(httpserver.url_for(""), connector="added_one", source="newsrc")
    app = App(config_dir=tmp_path, db=db, vault=vault, notifier=notifier)
    sched = HermesScheduler()
    assert sched.add_and_fetch(cfg, app) is True
    job = sched.get_job("added_one__first")
    assert job is not None  # the first fetch is queued the moment the connector is added
    seconds = (job.trigger.run_date - datetime.now(UTC)).total_seconds()
    assert seconds <= ADDED_RUN_DELAY_SECONDS + 1  # about one second, not the five of a start-up run
    assert db.count("events") == 0  # nothing yet: the job has not fired
    _run_job(cfg, app, sched)  # what the scheduler does a second later
    assert sources(db) == ["newsrc"] and db.count("events") == 2
    assert db.count_rows("quarantine", "added_one") == 1  # the invalid one is set aside, not shown
    with db.conn() as c:
        assert {r[0] for r in c.execute("SELECT connector FROM events")} == {"added_one"}
    assert sched.add_and_fetch(cfg, app) is False  # it has run now, so nothing more is scheduled


def test_a_disabled_connector_is_not_fetched(tmp_path: Path, db: Database, vault: SecretVault,
                                             notifier: RecordingNotifier) -> None:
    cfg = make_cfg("https://example.com", enabled=False)
    app = App(config_dir=tmp_path, db=db, vault=vault, notifier=notifier)
    assert HermesScheduler().add_and_fetch(cfg, app) is False


def test_the_page_says_the_first_records_are_being_fetched(tmp_path: Path, db: Database) -> None:
    hooks = ConnectorHooks(added=lambda owner, cfg: None, removed=lambda owner, name: None)
    with_hooks = create_app(tmp_path / "a", db, None, WebOptions(require_login=False, hooks=hooks))
    page = with_hooks.test_client().post("/connectors/new-yaml", data={"yaml_text": GOOD_YAML}).get_data(as_text=True)
    assert "Fetching its first records now" in page
    without = create_app(tmp_path / "b", db, None, WebOptions(require_login=False))
    quiet = without.test_client().post("/connectors/new-yaml", data={"yaml_text": GOOD_YAML}).get_data(as_text=True)
    assert "Fetching its first records now" not in quiet  # nothing is running to fetch it
