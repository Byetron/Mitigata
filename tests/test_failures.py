"""Failure scenarios (spec 8.1) and Feature B acceptance tests (B-1 to B-9)."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response

from conftest import FAKE_TOKEN, RecordingNotifier, advisory, make_cfg
from secintegrate import secrets
from secintegrate.classify import FailureCategory, classify_exception, classify_status
from secintegrate.logging_utils import RedactingFilter
from secintegrate.notify import StateChange, should_notify
from secintegrate.probe import probe_connector
from secintegrate.remediate import REMEDIATION, MessageContext, human_message
from secintegrate.runner import RunResult, run_connector
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database
from secintegrate.web.app import create_app


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return Response(json.dumps(data), status=status, content_type="application/json", headers=headers or {})


def _run(server: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier,
         sleeps: list[float] | None = None, **over: Any) -> RunResult:
    cfg = make_cfg(server.url_for(""), **over)
    sink = sleeps if sleeps is not None else []
    return run_connector(cfg, db, vault, notifier, sleep=sink.append)


def test_wrong_key_fails_fast_without_leaking(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                              notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_data("no", status=401)
    r = _run(httpserver, db, vault, notifier)
    assert r.status == "failed" and r.category is FailureCategory.AUTH_FAILED
    assert r.error is not None and "TEST_TOKEN" in r.error and FAKE_TOKEN not in r.error
    assert len(httpserver.log) == 1  # no retries
    assert FAKE_TOKEN not in str(db.health_rows())


def test_500_twice_then_success(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                notifier: RecordingNotifier) -> None:
    calls: list[int] = []

    def handler(request: Request) -> Response:
        calls.append(1)
        return _json([advisory(1)]) if len(calls) == 3 else Response("x", status=500)

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    sleeps: list[float] = []
    r = _run(httpserver, db, vault, notifier, sleeps)
    assert r.status == "success" and r.records_ok == 1 and sleeps == [1.0, 2.0]


def test_b4_429_waits_retry_after_then_succeeds(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                notifier: RecordingNotifier) -> None:
    calls: list[int] = []

    def handler(request: Request) -> Response:
        calls.append(1)
        if len(calls) == 1:
            return Response("slow down", status=429, headers={"Retry-After": "3"})
        return _json([advisory(1)])

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    sleeps: list[float] = []
    r = _run(httpserver, db, vault, notifier, sleeps)
    assert r.status == "success" and sleeps == [3.0]


def test_b5_one_bad_record_is_bad_data(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                       notifier: RecordingNotifier) -> None:
    bad = advisory(2)
    del bad["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), bad, advisory(3)])
    r = _run(httpserver, db, vault, notifier)
    assert r.status == "partial" and r.records_bad == 1 and r.records_ok == 2
    with db.conn() as c:
        row = c.execute("SELECT reason FROM quarantine").fetchone()
    assert row["reason"] == "required field missing: ghsa_id"
    assert r.message == "1 of 3 records invalid in the last run."


def test_b5_every_record_missing_a_required_field_is_schema_changed(
        httpserver: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    pages = []
    for i in (1, 2, 3):
        rec = advisory(i)
        del rec["ghsa_id"]
        pages.append(rec)
    httpserver.expect_request("/advisories").respond_with_json(pages)
    r = _run(httpserver, db, vault, notifier)
    assert r.status == "failed" and r.category is FailureCategory.SCHEMA_CHANGED
    assert r.message is not None and "Field `ghsa_id` is missing from the response" in r.message
    assert db.count("events") == 0 and db.count_rows("quarantine", "github_advisories") == 3
    assert db.get_cursor("github_advisories", "advisories") is None


def test_non_object_record_is_quarantined(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                          notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), "oops"])
    r = _run(httpserver, db, vault, notifier)
    assert r.status == "partial" and r.records_bad == 1


def test_network_loss_mid_run(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    import httpx

    def serve(request: httpx.Request) -> httpx.Response:
        if "page=2" in str(request.url):
            raise httpx.ConnectError("connection dropped", request=request)  # the network goes away after page 1
        link = '<https://api.example.test/advisories?page=2>; rel="next"'
        return httpx.Response(200, json=[advisory(1)], headers={"Link": link})

    cfg = make_cfg("https://api.example.test")
    sleeps: list[float] = []
    r = run_connector(cfg, db, vault, notifier, sleep=sleeps.append, transport=httpx.MockTransport(serve))
    assert r.status == "failed" and r.category is FailureCategory.NETWORK
    assert sleeps == [1.0, 2.0, 4.0]
    assert db.count("events") == 1  # page 1 kept
    assert db.get_cursor("github_advisories", "advisories") is None  # cursor not advanced
    assert r.message == ("Cannot reach `api.example.test`. Check network connectivity. "
                         "Hermes will retry automatically in 5 minutes.")


def test_incremental_second_run_uses_cursor(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                            notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), advisory(2)])
    _run(httpserver, db, vault, notifier)
    assert db.get_cursor("github_advisories", "advisories") == "2026-03-02T10:00:00Z"
    _run(httpserver, db, vault, notifier)
    first, second = (r[0].args.get("updated") for r in httpserver.log)
    assert first == ">=2026-01-01T00:00:00Z" and second == ">=2026-03-02T10:00:00Z"
    assert db.count("events") == 2


# --- B-1: every category is produced by a fixture ---------------------------------------------
@pytest.mark.parametrize(("status", "category"), [
    (401, FailureCategory.AUTH_FAILED), (403, FailureCategory.AUTH_FAILED), (404, FailureCategory.NOT_FOUND),
    (429, FailureCategory.RATE_LIMITED), (500, FailureCategory.SERVER_ERROR), (502, FailureCategory.SERVER_ERROR),
    (503, FailureCategory.SERVER_ERROR), (504, FailureCategory.SERVER_ERROR), (400, FailureCategory.CLIENT_ERROR),
    (422, FailureCategory.CLIENT_ERROR),
])
def test_b1_status_classification(status: int, category: FailureCategory) -> None:
    assert classify_status(status) is category
    assert classify_status(200) is None


def test_b1_exceptions_and_end_to_end_categories(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                 notifier: RecordingNotifier) -> None:
    import httpx

    assert classify_exception(httpx.ConnectError("x")) is FailureCategory.NETWORK
    assert classify_exception(httpx.ReadTimeout("x")) is FailureCategory.NETWORK
    assert classify_exception(RuntimeError("x")) is FailureCategory.UNKNOWN
    # produced by the runner end to end: not_found, client_error, bad_data (partial), schema_changed, unknown
    httpserver.expect_request("/advisories").respond_with_data("x", status=404)
    assert _run(httpserver, db, vault, notifier).category is FailureCategory.NOT_FOUND
    httpserver.clear()
    httpserver.expect_request("/advisories").respond_with_data("x", status=422)
    assert _run(httpserver, db, vault, notifier).category is FailureCategory.CLIENT_ERROR
    httpserver.clear()
    httpserver.expect_request("/advisories").respond_with_data("not json", status=200)
    assert _run(httpserver, db, vault, notifier).category is FailureCategory.UNKNOWN


def test_b2_every_category_has_exactly_one_remediation_entry() -> None:
    assert set(REMEDIATION) == set(FailureCategory)
    ctx = MessageContext(env_name="X_TOKEN", path="/p", host="h", field="f", status=422, n=1, total=2)
    for category in FailureCategory:
        message = human_message(category, ctx)
        assert message and "{" not in message  # every placeholder was filled
    # rate limiting is self-healing: its table entry has no template, and the message only exists
    # for the case where waits were exhausted
    assert REMEDIATION[FailureCategory.RATE_LIMITED].template is None


# --- B-3 and B-6: pause after 2 auth failures, notify on transitions only ---------------------
def test_b3_wrong_key_pauses_after_two_failures_with_one_notification(
        httpserver: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_data("no", status=401)
    first = _run(httpserver, db, vault, notifier)
    second = _run(httpserver, db, vault, notifier)
    third = _run(httpserver, db, vault, notifier)
    assert first.category is second.category is FailureCategory.AUTH_FAILED
    assert third.status == "paused" and len(httpserver.log) == 2
    assert db.get_connection("github_advisories")["status"] == "paused"  # type: ignore[index]
    assert [c.new_status for c in notifier.changes] == ["paused"]
    assert "secintegrate secret set TEST_TOKEN" in notifier.changes[0].message


def test_b6_ten_consecutive_failures_send_one_notification(
        httpserver: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    calls: list[int] = []

    def handler(request: Request) -> Response:
        calls.append(1)
        return _json([advisory(1)]) if len(calls) == 1 else Response("x", status=404)

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    assert _run(httpserver, db, vault, notifier).status == "success"  # healthy
    for _ in range(10):
        assert _run(httpserver, db, vault, notifier).status == "failed"
    assert [(c.old_status, c.new_status) for c in notifier.changes] == [("healthy", "failing")]


@pytest.mark.parametrize(("old", "new", "expected"), [
    ("healthy", "degraded", True), ("healthy", "failing", True), ("degraded", "paused", True),
    ("failing", "paused", True), ("degraded", "healthy", True), ("failing", "healthy", True),
    ("never_run", "failing", False), ("never_run", "healthy", False), ("failing", "failing", False),
    ("degraded", "failing", False), ("healthy", "healthy", False),
])
def test_b6_transition_rules(old: str, new: str, expected: bool) -> None:
    assert should_notify(old, new) is expected


def test_recovery_notifies(httpserver: HTTPServer, db: Database, vault: SecretVault,
                           notifier: RecordingNotifier) -> None:
    calls: list[int] = []

    def handler(request: Request) -> Response:
        calls.append(1)
        return _json([advisory(1)]) if len(calls) != 2 else Response("x", status=404)

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    for _ in range(3):
        _run(httpserver, db, vault, notifier)
    assert [(c.old_status, c.new_status) for c in notifier.changes] == [("healthy", "failing"),
                                                                        ("failing", "healthy")]


# --- B-7: no secret in messages, logs or the database -----------------------------------------
def test_b7_no_secret_in_messages_logs_or_health(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                 notifier: RecordingNotifier,
                                                 caplog: pytest.LogCaptureFixture) -> None:
    httpserver.expect_request("/advisories").respond_with_data(f"echo {FAKE_TOKEN}", status=401)
    with caplog.at_level(logging.DEBUG):
        _run(httpserver, db, vault, notifier)
        _run(httpserver, db, vault, notifier)
    blob = " ".join(c.message for c in notifier.changes) + str(db.health_rows())
    blob += json.dumps(db.latest_run("github_advisories"))
    assert FAKE_TOKEN not in blob
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "sent header %s", (FAKE_TOKEN,), None)
    RedactingFilter().filter(rec)
    assert FAKE_TOKEN not in rec.getMessage()


def test_secret_never_appears_in_logs() -> None:
    secrets.register(FAKE_TOKEN)
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "sent header %s", (FAKE_TOKEN,), None)
    RedactingFilter().filter(rec)
    assert FAKE_TOKEN not in rec.getMessage() and "***" in rec.getMessage()


# --- B-8: probes write no records --------------------------------------------------------------
def test_b8_probe_writes_no_records_and_stores_a_result(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                        notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/user").respond_with_json({"login": "x"})
    cfg = make_cfg(httpserver.url_for(""), probe={"path": "/user", "interval_minutes": 15})
    result = probe_connector(cfg, db, vault, notifier)
    assert result is not None and result.ok and result.status == 200
    assert db.count("events") == db.count("users") == db.count("devices") == 0
    assert db.latest_probe("github_advisories")["ok"] == 1  # type: ignore[index]
    assert httpserver.log[0][0].headers["Authorization"] == f"Bearer {FAKE_TOKEN}"


def test_probe_failures_are_classified_and_degrade_status(httpserver: HTTPServer, db: Database,
                                                          vault: SecretVault, notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_json([advisory(1)])
    httpserver.expect_request("/user").respond_with_data("down", status=503)
    cfg = make_cfg(httpserver.url_for(""), probe={"path": "/user"})
    run_connector(cfg, db, vault, notifier, sleep=lambda s: None)  # probe runs first (due), then sync
    conn = db.get_connection("github_advisories")
    assert conn is not None and conn["status"] == "degraded"
    assert db.latest_probe("github_advisories")["category"] == "server_error"  # type: ignore[index]
    assert conn["message"] == "Provider is returning server errors. Check its status page."


def test_probe_auth_failure_twice_pauses(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                         notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/user").respond_with_data("no", status=401)
    cfg = make_cfg(httpserver.url_for(""), probe={"path": "/user"})
    probe_connector(cfg, db, vault, notifier)
    probe_connector(cfg, db, vault, notifier)
    assert (db.get_connection("github_advisories") or {})["status"] == "paused"


def test_probe_rows_are_pruned_after_30_days(db: Database) -> None:
    db.add_probe("c", True, None, 200, 5)
    with db.conn() as c:
        c.execute("UPDATE probes SET checked_at='2020-01-01T00:00:00Z'")
    db.add_probe("c", True, None, 200, 5)
    assert db.count_rows("probes", "c") == 1


# --- B-9: the home page renders in each state --------------------------------------------------
def test_b9_home_renders_empty_never_run_and_paused(tmp_path: Path, db: Database) -> None:
    cfg_dir = tmp_path / "cfg"
    client = create_app(cfg_dir, db).test_client()
    assert client.get("/").status_code == 200  # no connectors
    cfg_dir.mkdir()
    (cfg_dir / "demo.yaml").write_text(
        "connector: demo\nsource: demo\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: none}\nendpoints: []\n", encoding="utf-8")
    page = client.get("/").get_data(as_text=True)
    assert "demo" in page and "never run" in page  # one never-run connector
    db.update_connection("demo", paused=1, status="paused", message="Credential `X` was rejected.")
    page = client.get("/").get_data(as_text=True)
    assert "paused" in page and "Credential `X` was rejected." in page


def test_state_change_dataclass_is_frozen() -> None:
    change = StateChange("c", "healthy", "failing", "m", "t")
    with pytest.raises(AttributeError):
        change.connector = "other"  # type: ignore[misc]


# --- notifications and resume ------------------------------------------------------------------
def test_webhook_body_has_only_the_agreed_information() -> None:
    import httpx

    from secintegrate.notify import WebhookNotifier

    sent: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200)

    hook = "https://hooks.example.com/" + "T0000/B0000"
    notifier = WebhookNotifier(lambda: hook, transport=httpx.MockTransport(handler))
    change = StateChange("demo", "healthy", "failing", "Provider is returning server errors.", "2026-10-31T00:00:00Z")
    notifier.notify(change)
    assert set(sent[0]) == {"connector", "status", "message", "timestamp", "text", "content"}
    assert sent[0]["status"] == "failing" and hook not in json.dumps(sent[0])


def test_webhook_failure_is_swallowed_and_never_logs_the_url(caplog: pytest.LogCaptureFixture) -> None:
    import httpx

    from secintegrate.notify import CompositeNotifier, WebhookNotifier

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    hook = "https://hooks.example.com/" + "T0000/B0000"
    notifier = CompositeNotifier([WebhookNotifier(lambda: hook, transport=httpx.MockTransport(boom))])
    with caplog.at_level(logging.DEBUG):
        notifier.notify(StateChange("demo", "healthy", "failing", "m", "t"))  # must not raise
    assert hook not in caplog.text


def test_new_secret_resumes_a_paused_connector(tmp_path: Path, db: Database, notifier: RecordingNotifier,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from secintegrate.cli import app as cli_app

    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "demo.yaml").write_text(
        "connector: demo\nsource: demo\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: bearer, secret: DEMO_TOKEN}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n"
        "      target: event\n      fields:\n        id: {from: id}\n        timestamp: {from: t}\n"
        "        severity: {from: s}\n", encoding="utf-8")
    db_file = str(tmp_path / "cli.db")
    from secintegrate.storage.db import Database as Db

    cli_db = Db(db_file)
    cli_db.update_connection("demo", paused=1, status="paused", consecutive_failures=2, message="rejected")
    monkeypatch.setattr("secintegrate.cli_secrets.getpass.getpass", lambda prompt="": FAKE_TOKEN)
    result = CliRunner().invoke(cli_app, ["secret", "set", "DEMO_TOKEN", "--db", db_file, "-c", str(cfg_dir)])
    assert result.exit_code == 0 and "Resumed demo." in result.output and FAKE_TOKEN not in result.output
    assert cli_db.get_connection("demo")["paused"] == 0  # type: ignore[index]
