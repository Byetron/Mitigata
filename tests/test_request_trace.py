"""The request record: every API call is noted without keeping anything that could leak."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx

from conftest import FAKE_TOKEN, RecordingNotifier, advisory, make_cfg
from secintegrate.http.client import ApiClient
from secintegrate.http.trace import RequestRecord
from secintegrate.probe import probe_connector
from secintegrate.runner import run_connector
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import REQUESTS_PER_CONNECTOR, Database

BASE = "https://api.example.test"


def serve(handler: httpx.MockTransport | None = None, status: int = 200, headers: dict[str, str] | None = None,
          body: object | None = None) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, json=body if body is not None else [advisory(1)],
                                                              headers=headers or {}))


def run(db: Database, vault: SecretVault, notifier: RecordingNotifier, transport: httpx.MockTransport,
        **over: object) -> None:
    run_connector(make_cfg(BASE, **over), db, vault, notifier, sleep=lambda s: None, transport=transport)


def test_a_run_leaves_a_record_with_status_timing_and_size(db: Database, vault: SecretVault,
                                                           notifier: RecordingNotifier) -> None:
    run(db, vault, notifier, serve(headers={"x-ratelimit-remaining": "4999", "retry-after": "7"}))
    rows = db.recent_requests("github_advisories")
    assert len(rows) == 1
    row = rows[0]
    assert (row["kind"], row["method"], row["host"], row["path"], row["status"]) == (
        "run", "GET", "api.example.test", "/advisories", 200)
    assert row["latency_ms"] >= 0 and row["bytes"] > 0 and row["content_type"] == "application/json"
    assert row["rate_remaining"] == "4999" and row["retry_after"] == "7" and row["error"] is None


def test_only_parameter_names_are_kept_never_their_values(db: Database, vault: SecretVault,
                                                          notifier: RecordingNotifier) -> None:
    run(db, vault, notifier, serve())
    row = db.recent_requests("github_advisories")[0]
    assert "updated" in row["params"]  # the name of the incremental filter
    assert "2026-01-01" not in json.dumps(row)  # but not the date that was sent


def test_no_secret_reaches_the_record(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    run(db, vault, notifier, serve())
    assert FAKE_TOKEN not in json.dumps(db.recent_requests("github_advisories"))


def test_every_attempt_is_recorded_including_retries(db: Database, vault: SecretVault,
                                                     notifier: RecordingNotifier) -> None:
    run(db, vault, notifier, serve(status=503, body={}))
    statuses = [r["status"] for r in db.recent_requests("github_advisories")]
    assert statuses == [503, 503, 503, 503]  # the first try and three retries


def test_a_request_that_gets_no_reply_is_recorded_with_the_error_type(db: Database, vault: SecretVault,
                                                                      notifier: RecordingNotifier) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    run(db, vault, notifier, httpx.MockTransport(refuse))
    row = db.recent_requests("github_advisories")[0]
    assert row["status"] is None and row["error"] == "ConnectError" and row["bytes"] is None


def test_probes_are_recorded_as_probes(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    cfg = make_cfg(BASE, probe={"path": "/ping"})
    probe_connector(cfg, db, vault, notifier, transport=serve())
    row = db.recent_requests("github_advisories")[0]
    assert row["kind"] == "probe" and row["path"] == "/ping"


def test_a_failing_recorder_never_breaks_the_request(db: Database, vault: SecretVault) -> None:
    def broken(record: RequestRecord) -> None:
        raise RuntimeError("disk full")

    client = ApiClient(make_cfg(BASE), vault, transport=serve(), recorder=broken)
    try:
        assert client.request("GET", f"{BASE}/advisories").data  # the call still works
    finally:
        client.close()


def test_the_record_is_capped_and_old_rows_are_pruned(db: Database) -> None:
    rec = RequestRecord("run", "GET", "h", "/p", "", 200, 5, 10, "application/json", None, None, None)
    for _ in range(REQUESTS_PER_CONNECTOR + 25):
        db.add_request("c", rec)
    assert db.count_rows("api_requests", "c") == REQUESTS_PER_CONNECTOR
    old = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db.conn() as c:
        c.execute("UPDATE api_requests SET at=?", (old,))
    db.add_request("c", rec)
    assert db.count_rows("api_requests", "c") == 1  # everything older than a week went


def test_removing_a_connector_clears_its_record(db: Database) -> None:
    rec = RequestRecord("run", "GET", "h", "/p", "", 200, 5, 10, None, None, None, None)
    db.add_request("gone", rec)
    db.add_request("kept", rec)
    db.delete_connector_state("gone")
    assert db.recent_requests("gone") == [] and len(db.recent_requests("kept")) == 1
