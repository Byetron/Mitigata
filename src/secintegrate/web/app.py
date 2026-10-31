"""Flask app: home dashboard with connector health (FR-10) and the connector form (B5)."""
from __future__ import annotations

from collections.abc import Callable, Collection
from pathlib import Path
from typing import Any

import yaml
from flask import Flask, Response, jsonify, redirect, render_template, request
from werkzeug.wrappers import Response as RedirectResponse

from ..config.loader import config_files, read_yaml
from ..config.schema import TARGET_FIELDS
from ..config.validator import ValidationIssue, existing_ids, has_errors, validate_text
from ..secrets import redact
from ..storage.db import Database
from ..transforms import TRANSFORMS
from . import forms

SecretNames = Callable[[], Collection[str]]


def _register_connections(config_dir: Path, db: Database) -> None:
    for f in config_files(config_dir):
        try:
            data = read_yaml(f)
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and isinstance(data.get("connector"), str):
            db.ensure_connection(data["connector"])


def create_app(config_dir: str | Path, db: Database, secret_names: SecretNames | None = None) -> Flask:
    """`secret_names` returns the names in the vault; None skips that validation rule."""
    config_dir = Path(config_dir)
    app = Flask(__name__)

    def validate_form(values: dict[str, Any]) -> tuple[str, list[ValidationIssue]]:
        text = yaml.safe_dump(forms.build_config(values), sort_keys=False)
        names = secret_names() if secret_names else None
        _, issues = validate_text(text, f"{values['connector_id'] or 'new'}.yaml", existing_ids(config_dir), names)
        return text, issues

    @app.get("/")
    def index() -> str:
        _register_connections(config_dir, db)
        source = request.args.get("source") or None
        data = db.dashboard(source)
        if source not in {s["source"] for s in data["event_sources"]}:
            source = None  # unknown filter: fall back to all events
            data = db.dashboard()
        configured = existing_ids(config_dir)
        conns = [c for c in db.health_rows() if c["connector"] in configured]  # hide removed connectors
        for c in conns:
            c["last_error"] = redact(c["last_error"]) if c["last_error"] else ""
            c["message"] = redact(c["message"]) if c.get("message") else ""
            c["spark"] = db.recent_probes(c["connector"], 24)
        counts = {s: sum(1 for c in conns if c["status"] == s)
                  for s in ("healthy", "degraded", "failing", "paused", "never_run")}
        return render_template("home.html", data=data, conns=conns, counts=counts, page="home", source=source)

    @app.get("/health")
    def health() -> RedirectResponse:
        return redirect("/")  # health lives on the home page

    def render_form(values: dict[str, Any], issues: list[ValidationIssue] | None = None,
                    result: dict[str, str] | None = None, status: int = 200) -> tuple[str, int]:
        by_field, general = forms.group_issues(issues or [])
        html = render_template(
            "new_connector.html", v=forms.safe_for_display(values), by_field=by_field, general=general,
            result=result, targets=TARGET_FIELDS, transforms=sorted(TRANSFORMS), page="new",
            presets=forms.presets(),
        )
        return html, status

    @app.get("/connectors/new")
    def new_connector() -> tuple[str, int]:
        return render_form(forms.default_values())

    @app.post("/connectors/validate-field")
    def validate_field() -> Response:
        """Validate the whole form (cross-field rules need it), return only one field's issues."""
        values = forms.parse_form(request.form)
        _, issues = validate_form(values)
        by_field, general = forms.group_issues(issues)
        field = request.form.get("field")
        chosen = by_field.get(field, []) if field else issues
        if field in ("mapping_target", "mapping") or (field or "").startswith("map_"):
            chosen = by_field.get("mapping", []) + by_field.get("mapping_target", [])
        del general
        return jsonify(field=field, issues=[{"message": i.message, "severity": i.severity} for i in chosen])

    @app.post("/connectors/new")
    def create_connector() -> tuple[str, int]:
        values = forms.parse_form(request.form)
        text, issues = validate_form(values)
        if has_errors(issues):
            return render_form(values, issues, status=400)
        filename = f"{values['connector_id']}.yaml"
        target = config_dir / filename
        config_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        db.ensure_connection(values["connector_id"])
        return render_form(values, issues, result={"yaml": text, "path": str(target)})

    return app
