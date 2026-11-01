"""Flask app: home dashboard with connector health, the connector form and YAML editor, removal, and sign-in.

Every page works on the signed-in account's own workspace (its connectors, records, health and keys).
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from flask import Flask, Response, abort, jsonify, redirect, render_template, request, session
from pydantic import ValidationError
from werkzeug.wrappers import Response as RedirectResponse

from ..config.loader import config_files, find_connector_file, parse_config, read_yaml
from ..config.schema import TARGET_FIELDS
from ..config.validator import ValidationIssue, existing_ids, has_errors, validate_text
from ..connector_files import remove_connector, template_text, write_connector
from ..diagnose import Diagnosis
from ..secrets import redact
from ..storage.db import Database
from ..suggest import suggest_fixes
from ..transforms import TRANSFORMS
from . import forms
from .auth import register_auth
from .options import SecretNames, WebContext, WebOptions

MAX_YAML_BYTES = 64 * 1024


def _register_connections(config_dir: Path, db: Database) -> None:
    for f in config_files(config_dir):
        try:
            data = read_yaml(f)
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and isinstance(data.get("connector"), str):
            db.ensure_connection(data["connector"])


_PROBLEM_ORDER = ("failing", "paused", "degraded")  # worst first
_PROBLEM_WORDS = {
    "failing": "is unavailable",
    "paused": "is paused",
    "degraded": "had a problem on its last update",
}


def _stored_issues(row: dict[str, Any] | None) -> tuple[list[dict[str, Any]], str | None]:
    """(issues, draft text) of a rejected edit; old rows held a bare list of issues."""
    if row is None:
        return [], None
    try:
        data = json.loads(row["issues"])
    except ValueError:
        return [], None
    if isinstance(data, list):
        return data, None
    return list(data.get("issues", [])), data.get("draft")


def _saved_diagnosis(db: Database, connector: str) -> Diagnosis | None:
    saved = db.get_diagnosis(connector)
    if saved is None:
        return None
    try:
        return Diagnosis.from_json(saved["report"])
    except (ValueError, KeyError, TypeError):
        return None


def _disabled_connectors(config_dir: Path) -> set[str]:
    """Connectors whose config says `enabled: false`: nothing schedules or runs them."""
    off: set[str] = set()
    for f in config_files(config_dir):
        try:
            cfg = parse_config(f)
        except (ValidationError, yaml.YAMLError):
            continue
        if not cfg.enabled:
            off.add(cfg.connector)
    return off


def source_freshness(config_dir: Path, db: Database, conns: list[dict[str, Any]],
                     sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add status, last good update and a plain message to each event source, so stale data is never silent."""
    by_connector = {c["connector"]: c for c in conns}
    owners: dict[str, list[str]] = {}
    for f in config_files(config_dir):
        try:
            cfg = parse_config(f)
        except (ValidationError, yaml.YAMLError):
            continue
        owners.setdefault(cfg.source, []).append(cfg.connector)
    out: list[dict[str, Any]] = []
    for s in sources:
        rows = [by_connector[i] for i in owners.get(s["source"], []) if i in by_connector]
        worst = next((r for state in _PROBLEM_ORDER for r in rows if r["status"] == state), None)
        last_ok = max((t for t in (db.last_success(r["connector"]) for r in rows) if t), default=None)
        out.append({**s, "status": worst["status"] if worst else "healthy",
                    "problem": _PROBLEM_WORDS.get(worst["status"], "") if worst else "",
                    "message": (worst or {}).get("message") or "", "last_ok": last_ok})
    return out


def create_app(config_dir: str | Path, db: Database, secret_names: SecretNames | None = None,
               options: WebOptions | None = None) -> Flask:
    """`db` holds the accounts. `config_dir`, `db` and `secret_names` are also the default workspace.

    When `options.workspaces` is set, a signed-in account gets its own workspace instead of the default one.
    `secret_names` returns the names in the vault; None skips that validation rule.
    """
    opts = options or WebOptions(require_login=False)
    default = WebContext(Path(config_dir), db, secret_names)
    app = Flask(__name__)
    register_auth(app, db, opts)

    def ctx() -> WebContext:
        user = session.get("user")
        if opts.workspaces is not None and opts.require_login and user:
            return opts.workspaces(str(user))
        return default

    def owner() -> str:
        return str(session.get("user") or "")

    def validate_form(values: dict[str, Any], c: WebContext) -> tuple[str, list[ValidationIssue]]:
        text = yaml.safe_dump(forms.build_config(values), sort_keys=False)
        names = c.secret_names() if c.secret_names else None
        _, issues = validate_text(text, f"{values['connector_id'] or 'new'}.yaml", existing_ids(c.config_dir),
                                  names, allow_internal=False)
        return text, issues

    def validate_yaml_text(text: str, c: WebContext) -> tuple[Any, list[ValidationIssue]]:
        names = c.secret_names() if c.secret_names else None
        return validate_text(text, "connector.yaml", existing_ids(c.config_dir), names, allow_internal=False)

    def announce(c: WebContext, path: Path, connector: str) -> None:
        c.db.ensure_connection(connector)
        if opts.hooks is not None:
            opts.hooks.added(owner(), parse_config(path))  # the running scheduler picks it up without a restart

    def fetching() -> str:
        """"yes" when the running scheduler will fetch the new connector's data by itself right away."""
        return "yes" if opts.hooks is not None else ""

    @app.get("/")
    def index() -> str:
        c = ctx()
        _register_connections(c.config_dir, c.db)
        source = request.args.get("source") or None
        data = c.db.dashboard(source)
        if source not in {s["source"] for s in data["event_sources"]}:
            source = None  # unknown filter: fall back to all events
            data = c.db.dashboard()
        configured = existing_ids(c.config_dir)
        disabled = _disabled_connectors(c.config_dir)
        conns = [r for r in c.db.health_rows() if r["connector"] in configured]  # hide removed connectors
        for r in conns:
            r["last_error"] = redact(r["last_error"]) if r["last_error"] else ""
            r["message"] = redact(r["message"]) if r.get("message") else ""
            r["spark"] = c.db.recent_probes(r["connector"], 24)
            saved_issues = c.db.get_config_issues(r["connector"])
            r["config_issues"] = _stored_issues(saved_issues)[0]
            if r["config_issues"] and r["status"] == "healthy":
                r["status"] = "degraded"  # the saved config is no longer what the user wants
                r["config_note"] = True
            r["diagnosis"] = _saved_diagnosis(c.db, r["connector"])
            if r["connector"] in disabled:  # not run by anything, so old failures must not stay on show
                r["status"] = "paused"
                r["disabled"] = True
                r["message"] = "Disabled in its config. Set enabled: true to run it again."
                r["diagnosis"] = None
            r["bad_requests"] = [] if r["connector"] in disabled else [
                q for q in c.db.recent_requests(r["connector"], 30) if q["status"] is None or q["status"] >= 400][:3]  # noqa: PLR2004
        counts = {s: sum(1 for r in conns if r["status"] == s)
                  for s in ("healthy", "degraded", "failing", "paused", "never_run")}
        data["event_sources"] = source_freshness(c.config_dir, c.db, conns, data["event_sources"])
        shown = [s for s in data["event_sources"] if not source or s["source"] == source]
        data["source_problems"] = [s for s in shown if s["problem"]]
        return render_template("home.html", data=data, conns=conns, counts=counts, page="home", source=source)

    @app.get("/health")
    def health() -> RedirectResponse:
        return redirect("/")  # health lives on the home page

    @app.post("/connectors/<connector>/delete")
    def delete_connector(connector: str) -> RedirectResponse:
        c = ctx()
        if remove_connector(c.config_dir, c.db, connector) is None:
            abort(404)
        if opts.hooks is not None:
            opts.hooks.removed(owner(), connector)
        return redirect("/")

    def edit_page(connector: str, text: str, issues: Sequence[Any], status: int = 200,
                  saved: bool = False, restored: bool = False) -> tuple[str, int]:
        return render_template("edit_connector.html", connector=connector, yaml_text=text, issues=issues,
                               saved=saved, restored=restored, page="home",
                               suggestions=suggest_fixes(text, _saved_diagnosis(ctx().db, connector))), status

    @app.get("/connectors/<connector>/edit")
    def edit_connector(connector: str) -> tuple[str, int]:
        file = find_connector_file(ctx().config_dir, connector)
        if file is None:
            abort(404)
        stored, draft = _stored_issues(ctx().db.get_config_issues(connector))
        if draft is not None:
            return edit_page(connector, draft, stored, restored=True)  # the unsaved draft, with its errors
        return edit_page(connector, file.read_text(encoding="utf-8"), [])

    @app.post("/connectors/<connector>/edit")
    def save_connector(connector: str) -> tuple[str, int]:
        c = ctx()
        file = find_connector_file(c.config_dir, connector)
        if file is None:
            abort(404)
        text = request.form.get("yaml_text") or ""
        if len(text.encode("utf-8")) > MAX_YAML_BYTES:
            abort(413)
        names = c.secret_names() if c.secret_names else None
        cfg, issues = validate_text(text, file.name, existing_ids(c.config_dir) - {connector}, names,
                                    allow_internal=False)
        if cfg is not None and cfg.connector != connector:
            issues.append(ValidationIssue("connector", 1, "The id cannot be changed here.", "error", file.name))
        if cfg is None or has_errors(issues):
            c.db.save_config_issues(connector, json.dumps({
                "issues": [{"line": i.line, "message": i.message, "severity": "error"}
                           for i in issues if i.severity == "error"], "draft": text}))
            return edit_page(connector, text, issues, 400)
        c.db.clear_config_issues(connector)
        write_connector(c.config_dir, connector, text if text.endswith("\n") else text + "\n")
        if opts.hooks is not None:
            opts.hooks.removed(owner(), connector)
            opts.hooks.added(owner(), cfg)
            if opts.hooks.run_now is not None:
                opts.hooks.run_now(owner(), connector)  # so the effect of the edit shows up straight away
        return edit_page(connector, text, issues, saved=True)

    def render_form(values: dict[str, Any], issues: list[ValidationIssue] | None = None,
                    result: dict[str, str] | None = None, status: int = 200, tab: str = "form",
                    yaml_text: str | None = None,
                    yaml_issues: list[ValidationIssue] | None = None) -> tuple[str, int]:
        by_field, general = forms.group_issues(issues or [])
        html = render_template(
            "new_connector.html", v=forms.safe_for_display(values), by_field=by_field, general=general,
            result=result, targets=TARGET_FIELDS, transforms=sorted(TRANSFORMS), page="new",
            presets=forms.presets(),
            public_feeds=forms.public_feeds(), tab=tab,
            yaml_text=yaml_text if yaml_text is not None else template_text(),
            yaml_issues=yaml_issues or [], template=template_text(),
        )
        return html, status

    @app.get("/connectors/new")
    def new_connector() -> tuple[str, int]:
        return render_form(forms.default_values(), tab="yaml" if request.args.get("tab") == "yaml" else "form")

    @app.post("/connectors/validate-field")
    def validate_field() -> Response:
        """Validate the whole form (cross-field rules need it), return only one field's issues."""
        values = forms.parse_form(request.form)
        _, issues = validate_form(values, ctx())
        by_field, _ = forms.group_issues(issues)
        field = request.form.get("field")
        chosen = by_field.get(field, []) if field else issues
        if field in ("mapping_target", "mapping") or (field or "").startswith("map_"):
            chosen = by_field.get("mapping", []) + by_field.get("mapping_target", [])
        return jsonify(field=field, issues=[{"message": i.message, "severity": i.severity} for i in chosen])

    @app.post("/connectors/new")
    def create_connector() -> tuple[str, int]:
        c = ctx()
        values = forms.parse_form(request.form)
        text, issues = validate_form(values, c)
        if has_errors(issues):
            return render_form(values, issues, status=400)
        path = write_connector(c.config_dir, values["connector_id"], text)
        announce(c, path, values["connector_id"])
        return render_form(values, issues, result={"yaml": text, "path": str(path), "fetching": fetching()})

    @app.post("/connectors/validate-yaml")
    def validate_yaml() -> Response:
        text = (request.form.get("yaml_text") or "")[:MAX_YAML_BYTES]
        _, issues = validate_yaml_text(text, ctx())
        return jsonify(issues=[{"line": i.line, "path": i.path, "message": i.message, "severity": i.severity}
                               for i in issues])

    @app.post("/connectors/new-yaml")
    def create_from_yaml() -> tuple[str, int]:
        c = ctx()
        text = request.form.get("yaml_text") or ""
        if len(text.encode("utf-8")) > MAX_YAML_BYTES:
            abort(413)
        cfg, issues = validate_yaml_text(text, c)
        if cfg is None or has_errors(issues):
            return render_form(forms.default_values(), status=400, tab="yaml", yaml_text=text, yaml_issues=issues)
        path = write_connector(c.config_dir, cfg.connector, text if text.endswith("\n") else text + "\n")
        announce(c, path, cfg.connector)
        return render_form(forms.default_values(), issues,
                           result={"yaml": text, "path": str(path), "fetching": fetching()}, tab="yaml", yaml_text=text)

    return app
