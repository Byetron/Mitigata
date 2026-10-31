"""Flask app: home with connector health (FR-10) and /connectors/new (B5)."""
from __future__ import annotations

from pathlib import Path

import yaml
from flask import Flask, redirect, render_template, request

from ..config.loader import config_files, read_yaml
from ..config.schema import TARGET_FIELDS
from ..config.validator import existing_ids, validate_text
from ..secrets import redact
from ..storage.db import Database
from ..transforms import TRANSFORMS
from . import forms


def _register_connections(config_dir: Path, db: Database) -> None:
    for f in config_files(config_dir):
        try:
            data = read_yaml(f)
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and isinstance(data.get("connector"), str):
            db.ensure_connection(data["connector"])


def create_app(config_dir: str | Path, db: Database) -> Flask:
    config_dir = Path(config_dir)
    app = Flask(__name__)

    @app.get("/")
    def index():
        _register_connections(config_dir, db)
        data = db.dashboard()
        configured = existing_ids(config_dir)
        conns = [c for c in db.health_rows() if c["connector"] in configured]  # hide removed connectors
        for c in conns:
            c["last_error"] = redact(c["last_error"]) if c["last_error"] else ""
        counts = {s: sum(1 for c in conns if c["status"] == s) for s in ("healthy", "degraded", "failing", "never_run")}
        return render_template("home.html", data=data, conns=conns, counts=counts, page="home")

    @app.get("/health")
    def health():
        return redirect("/")  # health now lives on the home page

    def render_form(values, errors=None, general=None, result=None):
        return render_template(
            "new_connector.html", v=values, errors=errors or {}, general=general or [], result=result,
            targets=TARGET_FIELDS, transforms=sorted(TRANSFORMS), page="new",
        )

    @app.get("/connectors/new")
    def new_connector():
        return render_form(forms.default_values())

    @app.post("/connectors/new")
    def create_connector():
        values = forms.parse_form(request.form)
        errors = forms.precheck(values)
        text = yaml.safe_dump(forms.build_config(values), sort_keys=False)
        filename = f"{values['connector_id'] or 'new'}.yaml"
        _, issues = validate_text(text, filename, existing_ids(config_dir))
        general: list[str] = []
        for issue in issues:
            name = forms.field_for_path(issue.path)
            if name:
                errors.setdefault(name, issue.message)
            else:
                general.append(f"{issue.path}: {issue.message}" if issue.path else issue.message)
        if errors or general:
            return render_form(values, errors, general), 400
        target = config_dir / filename
        config_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        db.ensure_connection(values["connector_id"])
        return render_form(values, result={"yaml": text, "path": str(target)})

    return app
