"""The toolbox and the auto-repair loop: safe fixes are applied and checked, the rest goes to a person."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from conftest import FAKE_TOKEN, RecordingNotifier, advisory, make_cfg
from secintegrate.diagnose import TlsInfo
from secintegrate.repair import repair
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database
from secintegrate.tools import Tool, ToolContext, ToolRegistry, ToolResult, default_registry

BASE = "https://api.example.test"


def ctx_for(db: Database, vault: SecretVault, notifier: RecordingNotifier, transport: httpx.MockTransport,
            **over: Any) -> ToolContext:
    return ToolContext(make_cfg(BASE, probe={"path": "/ping"}, **over), db, vault, notifier, transport=transport,
                       sleep=lambda s: None, resolver=lambda h: ["93.184.216.34"],
                       tls_check=lambda h, p: TlsInfo(True, 90, None))


def api(good_key: str = FAKE_TOKEN, fail: int | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if fail:
            return httpx.Response(fail, json={})
        if request.headers.get("authorization") != f"Bearer {good_key}":
            return httpx.Response(401, json={})
        if request.url.path == "/ping":
            return httpx.Response(200, json={})
        return httpx.Response(200, json=[advisory(1)])

    return httpx.MockTransport(handler)


def test_the_catalogue_is_shaped_like_mcp(db: Database, vault: SecretVault) -> None:
    tools = default_registry().list_tools()
    names = {t["name"] for t in tools}
    assert {"diagnose", "reprobe", "clean_secret", "resume", "rerun"} <= names
    for t in tools:
        assert t["description"] and t["inputSchema"]["type"] == "object" and "annotations" in t


def test_unknown_tools_and_bad_input_are_refused_and_logged(db: Database, vault: SecretVault,
                                                            notifier: RecordingNotifier) -> None:
    ctx = ctx_for(db, vault, notifier, api())
    reg = default_registry()
    assert not reg.call("nope", ctx).ok
    assert not reg.call("diagnose", ctx, {"surprise": 1}).ok
    assert len(db.recent_tool_calls("github_advisories")) == 2


def test_a_tool_that_is_not_safe_cannot_be_run_automatically(db: Database, vault: SecretVault,
                                                             notifier: RecordingNotifier) -> None:
    reg = ToolRegistry()
    reg.register(Tool("danger", "x", {"type": "object", "properties": {}}, lambda c, a: ToolResult(True, "ran"),
                      safe=False, changes_state=True))
    ctx = ctx_for(db, vault, notifier, api())
    assert not reg.call("danger", ctx, {}, caller="auto").ok
    assert reg.call("danger", ctx, {}, caller="user").ok


def test_a_crashing_tool_becomes_a_result_not_an_exception(db: Database, vault: SecretVault,
                                                           notifier: RecordingNotifier) -> None:
    def boom(c: ToolContext, a: dict[str, Any]) -> ToolResult:
        raise RuntimeError("secret " + FAKE_TOKEN)

    reg = ToolRegistry()
    reg.register(Tool("boom", "x", {"type": "object", "properties": {}}, boom, safe=True, changes_state=False))
    res = reg.call("boom", ctx_for(db, vault, notifier, api()), {}, "auto")
    assert not res.ok and FAKE_TOKEN not in res.message


def test_a_damaged_key_is_repaired_resumed_and_the_user_told(db: Database, vault: SecretVault,
                                                             notifier: RecordingNotifier) -> None:
    vault.store("TEST_TOKEN", chr(0xA0) + FAKE_TOKEN)
    db.ensure_connection("github_advisories")
    db.update_connection("github_advisories", paused=1, last_category="auth_failed", consecutive_failures=3)
    report = repair(ctx_for(db, vault, notifier, api()))
    assert report.before == "broken" and report.after == "healthy" and report.fixed
    assert [s.tool for s in report.steps][:2] == ["clean_secret", "resume"]
    assert vault.load("TEST_TOKEN").reveal() == FAKE_TOKEN  # the stored key is now clean
    assert not (db.get_connection("github_advisories") or {}).get("paused")
    assert any("Fixed automatically" in c.message for c in notifier.changes)


def test_a_key_the_api_still_refuses_is_left_alone_and_escalated(db: Database, vault: SecretVault,
                                                                 notifier: RecordingNotifier) -> None:
    vault.store("TEST_TOKEN", " wrong-key ")
    report = repair(ctx_for(db, vault, notifier, api()))
    assert report.after == "broken" and report.needs_human
    assert vault.load("TEST_TOKEN").reveal() == " wrong-key "  # never overwritten with a guess
    assert any("Needs a person" in c.message for c in notifier.changes)


def test_a_missing_key_is_never_guessed_at(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    cfg_over = {"auth": {"type": "bearer", "secret": "NOT_STORED"}}
    report = repair(ctx_for(db, vault, notifier, api(), **cfg_over))
    assert report.steps == [] and "hermes secret set NOT_STORED" in report.needs_human


def test_a_provider_outage_is_retried_and_does_not_pretend_to_be_fixed(db: Database, vault: SecretVault,
                                                                       notifier: RecordingNotifier) -> None:
    report = repair(ctx_for(db, vault, notifier, api(fail=503)))
    assert report.after == "broken" and not report.fixed
    assert report.steps and report.steps[0].tool == "reprobe" and not report.steps[0].ok


def test_a_recovered_outage_gets_rerun(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    ctx = ctx_for(db, vault, notifier, api(fail=503))
    repair(ctx)  # while the provider is down
    ctx.transport = api()  # the provider comes back
    db.ensure_connection("github_advisories")
    db.update_connection("github_advisories", paused=1, last_category="auth_failed")
    report = repair(ctx)
    assert report.fixed and "resume" in [s.tool for s in report.steps]


def test_a_healthy_connector_is_left_alone(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    report = repair(ctx_for(db, vault, notifier, api()))
    assert report.before == "healthy" and report.steps == [] and notifier.changes == []


def test_every_tool_call_is_logged_without_secrets(db: Database, vault: SecretVault,
                                                   notifier: RecordingNotifier) -> None:
    vault.store("TEST_TOKEN", chr(0xA0) + FAKE_TOKEN)
    repair(ctx_for(db, vault, notifier, api()))
    calls = db.recent_tool_calls("github_advisories")
    assert calls and {c["caller"] for c in calls} == {"auto"}
    assert FAKE_TOKEN not in str(calls)


def test_the_dashboard_shows_what_went_wrong(tmp_path: Any, db: Database, vault: SecretVault,
                                             notifier: RecordingNotifier) -> None:
    from secintegrate.web.app import create_app

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "github_advisories.yaml").write_text(
        "connector: github_advisories\nsource: github\nschedule: '0 * * * *'\nbase_url: https://api.example.test\n"
        "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
        "      fields:\n        id: {from: id, required: true}\n        type: {const: a}\n"
        "        severity: {const: low}\n        timestamp: {from: t, required: true, transform: iso8601}\n"
        "        description: {const: d}\n", encoding="utf-8")
    ctx = ctx_for(db, vault, notifier, api(fail=401))
    repair(ctx)
    html = create_app(cfg_dir, db).test_client().get("/").get_data(as_text=True)
    assert "What went wrong" in html and "rejected the login" in html
    assert FAKE_TOKEN not in html


def test_cli_diagnose_and_tools_run(tmp_path: Any) -> None:
    from typer.testing import CliRunner

    from secintegrate.cli import app

    out = CliRunner().invoke(app, ["tools"])
    assert out.exit_code == 0 and "clean_secret" in out.output
    args = ["diagnose", "nope", "--config-dir", str(tmp_path), "--db", str(tmp_path / "x.db")]
    missing = CliRunner().invoke(app, args)
    assert missing.exit_code == 2


def test_a_pending_retry_survives_a_restart(tmp_path: Any, db: Database, vault: SecretVault,
                                            notifier: RecordingNotifier) -> None:
    from datetime import UTC, datetime, timedelta

    from secintegrate.bootstrap import App
    from secintegrate.scheduler import HermesScheduler, _retry_id, _run_job

    cfg = make_cfg(BASE)
    app = App(config_dir=tmp_path, db=db, vault=vault, notifier=notifier)
    first = HermesScheduler()
    first.start(paused=True)
    first.add_connector(cfg, app)
    _run_job(cfg, app, first)  # the first try fails (no server): a retry is saved
    assert db.pending_retry("github_advisories") is not None
    second = HermesScheduler()  # a restart: a new scheduler, the same database
    second.start(paused=True)
    second.add_connector(cfg, app)
    job = second.get_job(_retry_id("github_advisories"))
    assert job is not None and job.next_run_time > datetime.now(UTC) - timedelta(seconds=1)


def test_edit_a_connector_from_its_card(tmp_path: Any, db: Database) -> None:
    from secintegrate.web.app import create_app

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    yaml_text = (
        "connector: edit_me\nsource: nvd\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
        "      fields:\n        id: {from: id, required: true}\n        type: {const: a}\n"
        "        severity: {const: low}\n        timestamp: {from: t, required: true, transform: iso8601}\n"
        "        description: {const: d}\n")
    (cfg_dir / "edit_me.yaml").write_text(yaml_text, encoding="utf-8")
    client = create_app(cfg_dir, db).test_client()
    assert "/connectors/edit_me/edit" in client.get("/").get_data(as_text=True)
    page = client.get("/connectors/edit_me/edit").get_data(as_text=True)
    assert "base_url: https://example.com" in page
    bad = client.post("/connectors/edit_me/edit", data={"yaml_text": yaml_text.replace("edit_me", "other")})
    assert bad.status_code == 400 and "cannot be changed" in bad.get_data(as_text=True)
    broken = client.post("/connectors/edit_me/edit", data={"yaml_text": "connector: ["})
    assert broken.status_code == 400
    ok = client.post("/connectors/edit_me/edit", data={"yaml_text": yaml_text.replace("0 * * * *", "*/5 * * * *")})
    assert ok.status_code == 200 and "Saved" in ok.get_data(as_text=True)
    assert "*/5 * * * *" in (cfg_dir / "edit_me.yaml").read_text(encoding="utf-8")
    assert client.get("/connectors/nope/edit").status_code == 404
    form = client.get("/connectors/new").get_data(as_text=True)
    assert 'name="base_url" value="" autocomplete="off" required' in form


def test_a_disabled_connector_is_never_run(db: Database, vault: SecretVault, notifier: RecordingNotifier) -> None:
    from secintegrate.bootstrap import App
    from secintegrate.scheduler import HermesScheduler

    cfg = make_cfg(BASE, enabled=False)
    sched = HermesScheduler()
    sched.start(paused=True)
    sched.add_connector(cfg, App(config_dir=Path("."), db=db, vault=vault, notifier=notifier))
    assert sched.entries == {} and sched.get_jobs() == []
    ctx = ToolContext(cfg, db, vault, notifier, transport=api(), sleep=lambda s: None)
    assert not default_registry().call("rerun", ctx, {}, "auto").ok


def test_a_rejected_edit_shows_on_the_card_until_fixed(tmp_path: Any, db: Database) -> None:
    from secintegrate.web.app import create_app

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    good = (
        "connector: edit_me\nsource: nvd\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
        "      fields:\n        id: {from: id, required: true}\n        type: {const: a}\n"
        "        severity: {const: low}\n        timestamp: {from: t, required: true, transform: iso8601}\n"
        "        description: {const: d}\n")
    (cfg_dir / "edit_me.yaml").write_text(good, encoding="utf-8")
    client = create_app(cfg_dir, db).test_client()
    client.get("/")
    db.update_connection("edit_me", status="healthy")
    client.post("/connectors/edit_me/edit", data={"yaml_text": good.replace("https://example.com", "ftp://x")})
    home = client.get("/").get_data(as_text=True)
    assert "was not saved" in home and "ftp://x" not in home and "degraded (config error)" in home
    assert "ftp://x" in client.get("/connectors/edit_me/edit").get_data(as_text=True)  # draft restored
    client.post("/connectors/edit_me/edit", data={"yaml_text": good})
    assert "was not saved" not in client.get("/").get_data(as_text=True)


def test_saving_does_not_double_blank_lines(tmp_path: Any, db: Database) -> None:
    from secintegrate.connector_files import write_connector

    write_connector(tmp_path, "edit_me", "connector: edit_me\r\nsource: x\r\n")
    assert (tmp_path / "edit_me.yaml").read_bytes() == b"connector: edit_me\nsource: x\n"


def test_editor_suggests_fixes_and_cards_use_short_labels(tmp_path: Any, db: Database) -> None:
    from secintegrate.suggest import suggest_fixes
    from secintegrate.web.app import create_app

    text = ("connector: feodo_c2\nsource: ofeod\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
            "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
            "      fields:\n        id: {from: id, required: true}\n")
    titles = {s.title: s for s in suggest_fixes(text)}
    assert titles["Source label looks mistyped"].new == "source: feodo"
    assert titles["Add a health check"].new.startswith("probe:\n  path: /x")
    assert suggest_fixes("connector: [") == []
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "feodo_c2.yaml").write_text(text, encoding="utf-8")
    client = create_app(cfg_dir, db).test_client()
    page = client.get("/connectors/feodo_c2/edit").get_data(as_text=True)
    assert "Suggested fixes" in page and "Apply to editor" in page
    home = client.get("/").get_data(as_text=True)
    assert "<dt>Failures</dt>" in home and "<dt>Quarantined</dt>" in home and "in a row" not in home


def test_a_disabled_connector_shows_as_paused_with_no_stale_failure(tmp_path: Any, db: Database) -> None:
    from secintegrate.web.app import create_app

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    text = (
        "connector: off_one\nsource: nvd\nenabled: false\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
        "      fields:\n        id: {from: id, required: true}\n        type: {const: a}\n"
        "        severity: {const: low}\n        timestamp: {from: t, required: true, transform: iso8601}\n"
        "        description: {const: d}\n")
    (cfg_dir / "off_one.yaml").write_text(text, encoding="utf-8")
    db.ensure_connection("off_one")
    db.update_connection("off_one", status="failing", message="old failure text", consecutive_failures=4)
    client = create_app(cfg_dir, db).test_client()
    html = client.get("/").get_data(as_text=True)
    assert "paused (disabled)" in html and "old failure text" not in html
    (cfg_dir / "off_one.yaml").write_text(text.replace("enabled: false", "enabled: true"), encoding="utf-8")
    assert "old failure text" in client.get("/").get_data(as_text=True)  # back to its real state when enabled


def test_a_valid_edit_runs_the_connector_soon(tmp_path: Any, db: Database, vault: SecretVault,
                                              notifier: RecordingNotifier) -> None:
    from secintegrate.bootstrap import App
    from secintegrate.scheduler import HermesScheduler
    from secintegrate.web.app import create_app
    from secintegrate.web.options import ConnectorHooks, WebOptions

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    text = (
        "connector: run_me\nsource: nvd\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
        "      fields:\n        id: {from: id, required: true}\n        type: {const: a}\n"
        "        severity: {const: low}\n        timestamp: {from: t, required: true, transform: iso8601}\n"
        "        description: {const: d}\n")
    (cfg_dir / "run_me.yaml").write_text(text, encoding="utf-8")
    sched = HermesScheduler()
    sched.start(paused=True)
    ws = App(config_dir=cfg_dir, db=db, vault=vault, notifier=notifier)
    hooks = ConnectorHooks(added=lambda e, c: sched.add_connector(c, ws),
                           removed=lambda e, n: sched.remove_connector(n),
                           run_now=lambda e, n: sched.run_soon(n))
    client = create_app(cfg_dir, db, options=WebOptions(require_login=False, hooks=hooks)).test_client()
    client.post("/connectors/run_me/edit", data={"yaml_text": text.replace("0 * * * *", "*/5 * * * *")})
    assert [j for j in sched.get_jobs() if j.id.startswith("run_me__edit")]
    client.post("/connectors/run_me/edit", data={"yaml_text": text.replace("schedule:", "enabled: false\nschedule:")})
    assert sched.run_soon("run_me") is False  # disabled: nothing is run


def test_a_run_uses_the_latest_settings_and_skips_a_removed_connector(db: Database, vault: SecretVault,
                                                                      notifier: RecordingNotifier,
                                                                      monkeypatch: Any) -> None:
    from secintegrate import scheduler as sch
    from secintegrate.bootstrap import App

    seen: list[str] = []

    def fake_run(cfg: Any, *a: Any, **k: Any) -> Any:
        seen.append(cfg.base_url)
        return type("R", (), {"retry_in_minutes": None})()

    monkeypatch.setattr(sch, "run_connector", fake_run)
    ws = App(config_dir=Path("."), db=db, vault=vault, notifier=notifier)
    sched = sch.HermesScheduler()
    sched.start(paused=True)
    old, new = make_cfg("https://old.example.test"), make_cfg("https://new.example.test")
    sched.add_connector(old, ws)
    sched.add_connector(new, ws)  # an edit replaced the settings
    sch._run_job(old, ws, sched)  # a job that still holds the old copy
    assert seen == ["https://new.example.test"]
    sched.remove_connector("github_advisories")
    sch._run_job(new, ws, sched)  # removed while waiting: not run
    assert seen == ["https://new.example.test"]


def test_a_run_re_tests_a_failing_probe_so_a_fix_clears_it(db: Database, vault: SecretVault,
                                                           notifier: RecordingNotifier) -> None:
    from secintegrate.runner import run_connector

    cfg = make_cfg(BASE, probe={"path": "/ping", "interval_minutes": 60})
    db.ensure_connection("github_advisories")
    db.add_probe("github_advisories", False, "network", None, None)  # an old failure, not yet due again
    run_connector(cfg, db, vault, notifier, sleep=lambda s: None, transport=api())
    assert (db.latest_probe("github_advisories") or {}).get("ok") == 1
    assert (db.get_connection("github_advisories") or {}).get("status") == "healthy"
