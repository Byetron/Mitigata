"""Section 8.1 failure scenarios against a local mock server."""
import json
import logging

from werkzeug.wrappers import Response

from conftest import advisory, make_cfg
from secintegrate import secrets
from secintegrate.logging_utils import RedactingFilter
from secintegrate.runner import run_connector

TOKEN = "tok-SECRET-value-123"


def _run(httpserver, db, monkeypatch, sleeps=None, **over):
    monkeypatch.setenv("TEST_TOKEN", TOKEN)
    cfg = make_cfg(httpserver.url_for(""), **over)
    sleeps = sleeps if sleeps is not None else []
    return run_connector(cfg, db, sleep=sleeps.append)


def _json(data, status=200, headers=None):
    return Response(json.dumps(data), status=status, content_type="application/json", headers=headers or {})


def test_wrong_key_fails_fast_without_leaking(httpserver, db, monkeypatch):
    httpserver.expect_request("/advisories").respond_with_data("no", status=401)
    r = _run(httpserver, db, monkeypatch)
    assert r.status == "failed" and r.error.startswith("auth_failed")
    assert "TEST_TOKEN" in r.error and TOKEN not in r.error
    assert len(httpserver.log) == 1  # no retries
    assert db.get_connection("github_advisories")["status"] == "failing"
    assert TOKEN not in str(db.health_rows())


def test_500_twice_then_success(httpserver, db, monkeypatch):
    calls = []

    def handler(request):
        calls.append(1)
        return _json([advisory(1)]) if len(calls) == 3 else Response("x", status=500)

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    sleeps = []
    r = _run(httpserver, db, monkeypatch, sleeps)
    assert r.status == "success" and r.records_ok == 1
    assert sleeps == [1.0, 2.0]


def test_429_waits_retry_after(httpserver, db, monkeypatch):
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return Response("slow down", status=429, headers={"Retry-After": "3"})
        return _json([advisory(1)])

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    sleeps = []
    r = _run(httpserver, db, monkeypatch, sleeps)
    assert r.status == "success" and sleeps == [3.0]


def test_missing_required_field_is_quarantined(httpserver, db, monkeypatch):
    bad = advisory(2)
    del bad["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), bad, advisory(3)])
    r = _run(httpserver, db, monkeypatch)
    assert r.status == "partial" and r.records_bad == 1 and r.records_ok == 2
    with db.conn() as c:
        row = c.execute("SELECT reason FROM quarantine").fetchone()
    assert row["reason"] == "required field missing: ghsa_id"
    assert db.get_connection("github_advisories")["status"] == "degraded"


def test_non_object_record_is_quarantined(httpserver, db, monkeypatch):
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), "oops"])
    r = _run(httpserver, db, monkeypatch)
    assert r.status == "partial" and r.records_bad == 1


def test_network_loss_mid_run(httpserver, db, monkeypatch):
    nxt = "http://127.0.0.1:1/advisories?page=2"
    httpserver.expect_request("/advisories").respond_with_handler(
        lambda req: _json([advisory(1)], headers={"Link": f'<{nxt}>; rel="next"'}))
    sleeps = []
    r = _run(httpserver, db, monkeypatch, sleeps)
    assert r.status == "failed" and r.error.startswith("network_error")
    assert sleeps == [1.0, 2.0, 4.0]
    assert db.count("events") == 1            # page 1 kept
    assert db.get_cursor("github_advisories", "advisories") is None  # cursor not advanced


def test_incremental_second_run_uses_cursor(httpserver, db, monkeypatch):
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), advisory(2)])
    _run(httpserver, db, monkeypatch)
    assert db.get_cursor("github_advisories", "advisories") == "2026-03-02T10:00:00Z"
    _run(httpserver, db, monkeypatch)
    first, second = (r[0].args.get("updated") for r in httpserver.log)
    assert first == ">=2026-01-01T00:00:00Z"
    assert second == ">=2026-03-02T10:00:00Z"
    assert db.count("events") == 2           # upserts are idempotent


def test_secret_never_appears_in_logs():
    secrets.register(TOKEN)
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "sent header %s", (TOKEN,), None)
    RedactingFilter().filter(rec)
    assert TOKEN not in rec.getMessage() and "***" in rec.getMessage()
