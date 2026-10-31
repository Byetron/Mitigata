"""Automatic recovery: retry soon, auto-resume, and re-trying stored bad records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pytest_httpserver import HTTPServer
from werkzeug.wrappers import Request, Response

from conftest import RecordingNotifier, advisory, make_cfg
from secintegrate.autoheal import reprocess_quarantine, retry_delay_minutes
from secintegrate.bootstrap import App
from secintegrate.classify import FailureCategory
from secintegrate.probe import recheck_paused
from secintegrate.runner import RunResult, run_connector
from secintegrate.scheduler import _retry_id, _run_job, build_scheduler
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database


@pytest.mark.parametrize(("category", "failures", "expected"), [
    (FailureCategory.SERVER_ERROR, 1, 5), (FailureCategory.NETWORK, 2, 15), (FailureCategory.RATE_LIMITED, 3, 45),
    (FailureCategory.SERVER_ERROR, 4, None),    # after three early retries, wait for the normal schedule
    (FailureCategory.AUTH_FAILED, 1, None),     # a rejected key will not fix itself
    (FailureCategory.NOT_FOUND, 1, None), (FailureCategory.SCHEMA_CHANGED, 1, None), (None, 1, None),
])
def test_retry_delay_rules(category: FailureCategory | None, failures: int, expected: int | None) -> None:
    assert retry_delay_minutes(category, failures) == expected


def _run(server: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier, **over: Any) -> RunResult:
    return run_connector(make_cfg(server.url_for(""), **over), db, vault, notifier, sleep=lambda s: None)


def test_transient_failures_get_growing_retry_delays(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                     notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_data("x", status=500)
    delays = [_run(httpserver, db, vault, notifier).retry_in_minutes for _ in range(4)]
    assert delays == [5, 15, 45, None]


def test_retry_message_is_shown_on_the_connection(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                  notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_data("x", status=503)
    _run(httpserver, db, vault, notifier)
    conn = db.get_connection("github_advisories")
    assert conn is not None and "Hermes will retry automatically in 5 minutes." in conn["message"]


def test_auth_failures_are_never_scheduled_for_retry(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                     notifier: RecordingNotifier) -> None:
    httpserver.expect_request("/advisories").respond_with_data("no", status=401)
    assert _run(httpserver, db, vault, notifier).retry_in_minutes is None


def test_scheduler_adds_then_clears_a_retry_job(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                notifier: RecordingNotifier) -> None:
    calls: list[int] = []

    def handler(request: Request) -> Response:
        calls.append(1)
        if len(calls) == 1:
            return Response("x", status=500)
        return Response(json.dumps([advisory(1)]), content_type="application/json")

    httpserver.expect_request("/advisories").respond_with_handler(handler)
    cfg = make_cfg(httpserver.url_for(""), retry={"max_retries": 0})  # no in-run retry: the failure surfaces
    app = App(config_dir=Path("."), db=db, vault=vault, notifier=notifier)
    sched = build_scheduler([cfg], app)
    _run_job(cfg, app, sched)
    assert sched.get_job(_retry_id("github_advisories")) is not None  # failed, so a retry is queued
    _run_job(cfg, app, sched)  # the retry succeeds
    assert sched.get_job(_retry_id("github_advisories")) is None


def test_quarantine_is_not_duplicated_between_runs(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                                   notifier: RecordingNotifier) -> None:
    bad = advisory(2)
    del bad["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), bad])
    for _ in range(3):
        _run(httpserver, db, vault, notifier)
    assert db.count_rows("quarantine", "github_advisories") == 1


def test_quarantined_records_are_saved_once_the_mapping_is_fixed(
        httpserver: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    odd = advisory(2, alt_id="GHSA-FIXED")
    del odd["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), odd])
    assert _run(httpserver, db, vault, notifier).status == "partial"
    assert db.count_rows("quarantine", "github_advisories") == 1 and db.count("events") == 1
    fixed = make_cfg(httpserver.url_for(""))
    fixed.endpoints[0].mapping.fields["id"].from_ = "alt_id"  # the human fixes the mapping
    assert reprocess_quarantine(fixed, db) == 1
    assert db.count_rows("quarantine", "github_advisories") == 0 and db.count("events") == 2


def test_still_bad_records_stay_quarantined(httpserver: HTTPServer, db: Database, vault: SecretVault,
                                            notifier: RecordingNotifier) -> None:
    bad = advisory(2)
    del bad["ghsa_id"]
    httpserver.expect_request("/advisories").respond_with_json([advisory(1), bad])
    _run(httpserver, db, vault, notifier)
    assert reprocess_quarantine(make_cfg(httpserver.url_for("")), db) == 0
    assert db.count_rows("quarantine", "github_advisories") == 1


def test_paused_connector_resumes_when_the_credential_works_again(
        httpserver: HTTPServer, db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    state = {"status": 401}

    def handler(request: Request) -> Response:
        return Response("x", status=state["status"])

    httpserver.expect_request("/user").respond_with_handler(handler)
    cfg = make_cfg(httpserver.url_for(""), probe={"path": "/user"})
    db.update_connection("github_advisories", paused=1, status="paused", last_category="auth_failed",
                         consecutive_failures=2, message="rejected")
    assert recheck_paused(cfg, db, vault, notifier) is False  # still rejected: stays paused
    assert (db.get_connection("github_advisories") or {})["paused"] == 1
    state["status"] = 200
    assert recheck_paused(cfg, db, vault, notifier) is True
    conn = db.get_connection("github_advisories") or {}
    assert conn["paused"] == 0 and conn["consecutive_failures"] == 0 and conn["status"] != "paused"


def test_recheck_does_nothing_without_a_probe_or_pause(db: Database, vault: SecretVault,
                                                       notifier: RecordingNotifier) -> None:
    cfg = make_cfg("https://example.com")
    assert recheck_paused(cfg, db, vault, notifier) is False
    db.update_connection("github_advisories", paused=1, last_category="auth_failed")
    assert recheck_paused(cfg, db, vault, notifier) is False  # no probe configured


def test_connectors_that_never_ran_get_a_first_run_at_startup(db: Database, vault: SecretVault,
                                                              notifier: RecordingNotifier) -> None:
    from secintegrate.scheduler import schedule_first_runs

    fresh = make_cfg("https://example.com")
    done = make_cfg("https://example.com", connector="already_ran")
    off = make_cfg("https://example.com", connector="switched_off", enabled=False)
    db.update_connection("already_ran", status="healthy")
    app = App(config_dir=Path("."), db=db, vault=vault, notifier=notifier)
    sched = build_scheduler([fresh, done, off], app)
    assert schedule_first_runs(sched, [fresh, done, off], app) == ["github_advisories"]
    assert sched.get_job("github_advisories__first") is not None
    assert sched.get_job("already_ran__first") is None and sched.get_job("switched_off__first") is None
