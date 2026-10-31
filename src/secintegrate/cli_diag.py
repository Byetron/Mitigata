"""Commands that inspect and repair integrations: diagnose, repair, tools."""
from __future__ import annotations

from pathlib import Path

import typer

from .cli_common import CONFIG_DIR, DB_OPTION, USER_OPTION, friendly_errors, workspace_app
from .config.loader import find_connector_file, parse_config
from .diagnose import Diagnosis
from .repair import repair
from .tools import ToolContext, default_registry

ICON = {"ok": "[ ok ]", "info": "[info]", "warn": "[warn]", "error": "[FAIL]"}


def _context(connector: str, user: str | None, config_dir: Path, db_path: Path | None) -> ToolContext:
    app = workspace_app(user, config_dir, db_path)
    file = find_connector_file(app.config_dir, connector)
    if file is None:
        typer.echo(f"No connector '{connector}' found in {app.config_dir}.")
        raise typer.Exit(2)
    return ToolContext(parse_config(file), app.db, app.vault, app.notifier)


def print_diagnosis(d: Diagnosis) -> None:
    typer.echo(f"{d.connector}: {d.verdict.upper()}")
    typer.echo(d.summary)
    typer.echo("")
    for f in d.findings:
        typer.echo(f"{ICON[f.level]} {f.title}")
        if f.level != "ok":
            typer.echo(f"        {f.detail}")
            if f.fix:
                typer.echo(f"        Fix: {f.fix}")


@friendly_errors
def diagnose_cmd(connector: str = typer.Argument(..., help="Connector id."), config_dir: Path = CONFIG_DIR,
                 db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Check a connector's config, key, network and live API, and say what is wrong."""
    ctx = _context(connector, user, config_dir, db_path)
    result = default_registry().call("diagnose", ctx, {}, caller="user")
    saved = ctx.db.get_diagnosis(connector)
    if saved:
        print_diagnosis(Diagnosis.from_json(saved["report"]))
    else:
        typer.echo(result.message)
    if not result.ok:
        raise typer.Exit(1)


@friendly_errors
def repair_cmd(connector: str = typer.Argument(..., help="Connector id."), config_dir: Path = CONFIG_DIR,
               db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Diagnose, apply the safe automatic fixes, and check again."""
    ctx = _context(connector, user, config_dir, db_path)
    report = repair(ctx, caller="user")
    typer.echo(f"{connector}: {report.before} -> {report.after}")
    for s in report.steps:
        typer.echo(f"  {'done' if s.ok else 'no  '}  {s.tool}: {s.message}")
    if report.needs_human:
        typer.echo(f"Needs a person: {report.needs_human}")
        raise typer.Exit(1)
    if not report.steps and report.before == "healthy":
        typer.echo("Nothing to repair.")


def tools_cmd() -> None:
    """List the tools Hermes can use to inspect and repair integrations."""
    for t in default_registry().list_tools():
        mode = "read-only" if t["annotations"]["readOnlyHint"] else "changes state"
        typer.echo(f"{t['name']:<22} {mode:<14} {t['description']}")
