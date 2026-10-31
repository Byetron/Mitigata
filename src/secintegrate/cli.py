"""Command line interface (spec 7.1 and brief 1.4, 3.5).

Commands work on the default workspace, or on one account's own connectors and keys with `--user EMAIL`.
"""
from __future__ import annotations

import logging
import secrets
from pathlib import Path

import typer

from .bootstrap import App, build_app
from .cli_auth import auth_app
from .cli_common import CONFIG_DIR, DB_OPTION, USER_OPTION, friendly_errors, resolve_db, workspace_app
from .cli_secrets import secret_app
from .config.loader import config_files, find_connector_file, parse_config
from .config.schema import ConnectorConfig
from .config.validator import has_errors, validate_dir, validate_paths
from .connector_files import remove_connector, template_text
from .health import refresh_connection
from .logging_utils import setup_logging
from .security.errors import SecretNotFoundError

app = typer.Typer(help="Hermes: config-driven security integration platform.", no_args_is_help=True)
db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
app.add_typer(db_app, name="db")
app.add_typer(secret_app, name="secret")
app.add_typer(auth_app, name="auth")


def _valid_configs(ctx: App) -> list[ConnectorConfig]:
    """Configs without errors. Others are skipped with a warning in the log."""
    log = logging.getLogger("secintegrate")
    bad = {Path(i.file) for i in validate_dir(ctx.config_dir, ctx.vault.list_names()) if i.severity == "error"}
    configs: list[ConnectorConfig] = []
    for f in config_files(ctx.config_dir):
        if f in bad:
            log.warning("skipping %s: it has errors (run `hermes validate`)", f)
            continue
        configs.append(parse_config(f))
    return configs


@app.command()
@friendly_errors
def init(db_path: Path | None = DB_OPTION, config_dir: Path = CONFIG_DIR) -> None:
    """Set everything up: master key, database and tables, probe schedule. Safe to run again."""
    from .scheduler import build_scheduler

    ctx = build_app(config_dir, resolve_db(db_path))
    ctx.vault.init_key()
    for cfg in _valid_configs(ctx):
        ctx.db.ensure_connection(cfg.connector)
    jobs = len(build_scheduler(_valid_configs(ctx), ctx).get_jobs())
    typer.echo(f"Hermes is ready. Data is stored in: {resolve_db(db_path)}")
    typer.echo(f"{jobs} scheduled job(s) (runs and probes) are configured.")
    typer.echo("The master key is held by the OS keychain (or SECINTEGRATE_MASTER_KEY). It is never printed.")


@app.command()
@friendly_errors
def validate(path: Path = typer.Argument(None, help="A file or directory (default: the workspace's connectors)."),
             config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Validate connector configs. Exit 1 if any have errors (warnings do not fail)."""
    ctx = workspace_app(user, config_dir, db_path)
    target = path or ctx.config_dir
    secret_names = ctx.vault.list_names()
    if target.is_file():
        issues, count = validate_paths([target], secret_names), 1
    else:
        issues, count = validate_dir(target, secret_names), len(config_files(target))
    for issue in issues:
        typer.echo(str(issue))
    errors = [i for i in issues if i.severity == "error"]
    if errors:
        typer.echo(f"{len(errors)} error(s), {len(issues) - len(errors)} warning(s).")
        raise typer.Exit(1)
    typer.echo(f"OK: {count} config file(s) valid, {len(issues)} warning(s).")


@app.command()
@friendly_errors
def run(connector: str = typer.Argument(..., help="Connector id."),
        once: bool = typer.Option(True, "--once", help="Run once now (default)."),
        no_throttle: bool = typer.Option(False, "--no-throttle", help="Disable the client-side rate limit."),
        config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Run one connector now."""
    from .runner import run_connector

    del once  # accepted for compatibility: a run is always one pass
    setup_logging("logs")
    ctx = workspace_app(user, config_dir, db_path)
    file = find_connector_file(ctx.config_dir, connector)
    if file is None:
        typer.echo(f"No connector '{connector}' found in {ctx.config_dir}.")
        raise typer.Exit(2)
    issues = [i for i in validate_dir(ctx.config_dir, ctx.vault.list_names()) if Path(i.file) == file]
    if has_errors(issues):
        for i in issues:
            typer.echo(str(i))
        typer.echo("Refusing to run a config that has errors.")
        raise typer.Exit(1)
    result = run_connector(parse_config(file), ctx.db, ctx.vault, ctx.notifier, throttle=not no_throttle)
    typer.echo(result.summary)
    typer.echo(f"pages={result.pages} requests={result.requests} records_ok={result.records_ok} "
               f"records_bad={result.records_bad} seconds={result.seconds:.1f}")
    if result.status in ("failed", "paused"):
        raise typer.Exit(1)


@app.command()
def template(out: Path | None = typer.Option(None, "--out", help="Write to a file instead of the screen.")) -> None:
    """Print a commented connector template. Copy it to config/connectors/ and edit it."""
    text = template_text()
    if out is None:
        typer.echo(text)
        return
    if out.exists():
        typer.echo(f"{out} already exists. Nothing was written.")
        raise typer.Exit(1)
    out.write_text(text, encoding="utf-8")
    typer.echo(f"Wrote {out}")


@app.command()
@friendly_errors
def remove(connector: str = typer.Argument(..., help="Connector id to remove."),
           yes: bool = typer.Option(False, "--yes", help="Skip confirmation."),
           config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Remove a connector. Its config goes to .trash; its health history and fetched records are deleted."""
    if not yes:
        typer.confirm(f"Remove {connector}?", abort=True)
    ctx = workspace_app(user, config_dir, db_path)
    removed = remove_connector(ctx.config_dir, ctx.db, connector)
    if removed is None:
        typer.echo(f"No connector '{connector}' found in {ctx.config_dir}.")
        raise typer.Exit(2)
    typer.echo(f"Removed {connector} and deleted {removed.records} fetched record(s). "
               f"Its config was kept at {removed.config}.")


@app.command()
@friendly_errors
def resume(connector: str = typer.Argument(..., help="Connector id to resume."),
           config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Un-pause a connector that was paused after repeated auth failures."""
    ctx = workspace_app(user, config_dir, db_path)
    if ctx.db.get_connection(connector) is None:
        typer.echo(f"No connector '{connector}' has run yet.")
        raise typer.Exit(2)
    refresh_connection(ctx.db, ctx.notifier, connector, paused=0, consecutive_failures=0, message=None)
    typer.echo(f"Resumed {connector}.")


@app.command()
@friendly_errors
def serve(port: int = typer.Option(8000, "--port"), config_dir: Path = CONFIG_DIR,
          db_path: Path | None = DB_OPTION) -> None:
    """Start the scheduler and the web server (127.0.0.1 only). Every account's connectors run."""
    from .scheduler import HermesScheduler, schedule_first_runs
    from .web.app import create_app
    from .web.google import GoogleCredentials
    from .web.options import ConnectorHooks, WebOptions
    from .workspaces import WorkspaceManager

    setup_logging("logs")
    log = logging.getLogger("secintegrate")
    system = build_app(config_dir, resolve_db(db_path))  # the original workspace; it also holds the accounts
    manager = WorkspaceManager(system.db, config_dir, resolve_db(db_path))
    manager.legacy_owner()  # settle who owns the connectors that existed before accounts
    sched = HermesScheduler()
    loaded = 0

    def load(workspace: App, owner: str) -> None:
        nonlocal loaded
        configs = _valid_configs(workspace)
        for cfg in configs:
            workspace.db.ensure_connection(cfg.connector)
            sched.add_connector(cfg, workspace, owner)
        schedule_first_runs(sched, configs, workspace, owner)
        loaded += sum(c.enabled for c in configs)

    load(system, "")
    for account in system.db.list_app_users():
        email = str(account["email"])
        if not manager.is_legacy(email):
            load(manager.app_for(email), email)  # an account's connectors run under its own keys
    sched.install_recheck()
    sched.start()

    def scheduler_owner(email: str) -> str:
        return "" if not email or manager.is_legacy(email) else email

    def connector_added(email: str, cfg: ConnectorConfig) -> None:
        workspace = manager.app_for(email) if email else system
        sched.add_and_fetch(cfg, workspace, scheduler_owner(email))  # data is fetched now, not at the next cron time

    def session_secret() -> str:
        try:
            return system.vault.load("SESSION_SECRET").reveal()
        except SecretNotFoundError:
            value = secrets.token_hex(32)
            system.vault.store("SESSION_SECRET", value)
            return value

    def google_credentials() -> GoogleCredentials | None:
        try:
            return GoogleCredentials(system.vault.load("GOOGLE_CLIENT_ID").reveal(),
                                     system.vault.load("GOOGLE_CLIENT_SECRET").reveal())
        except SecretNotFoundError:
            return None

    options = WebOptions(
        session_secret=session_secret(), google=google_credentials, public_url=f"http://127.0.0.1:{port}",
        hooks=ConnectorHooks(added=connector_added,
                             removed=lambda email, name: sched.remove_connector(name, scheduler_owner(email))),
        workspaces=manager.web_context,
    )
    log.info("scheduled %d connector(s); dashboard at http://127.0.0.1:%d/ (sign-in required)", loaded, port)
    try:
        create_app(config_dir, system.db, system.vault.list_names, options).run(
            host="127.0.0.1", port=port, use_reloader=False)
    finally:
        sched.shutdown(wait=False)


@app.command()
@friendly_errors
def status(config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION, user: str | None = USER_OPTION) -> None:
    """Print the health table."""
    from .web.app import _register_connections

    ctx = workspace_app(user, config_dir, db_path)
    _register_connections(ctx.config_dir, ctx.db)
    configured = {c.connector for c in _valid_configs(ctx)}
    head = f"{'connector':<20}{'status':<10}{'last run':<22}{'pulled':>7}{'bad':>5}{'fails':>6}  message"
    typer.echo(head)
    typer.echo("-" * len(head))
    for r in ctx.db.health_rows():
        if r["connector"] not in configured:
            continue
        bad = "-" if r["last_bad"] is None else r["last_bad"]
        typer.echo(f"{r['connector']:<20}{r['status']:<10}{(r['last_run_finished_at'] or '-'):<22}"
                   f"{r['last_records_pulled'] or 0:>7}{bad:>5}{r['consecutive_failures'] or 0:>6}  "
                   f"{r['message'] or ''}")


@db_app.command("reset")
@friendly_errors
def db_reset(db_path: Path | None = DB_OPTION, config_dir: Path = CONFIG_DIR, user: str | None = USER_OPTION,
             yes: bool = typer.Option(False, "--yes", help="Skip confirmation.")) -> None:
    """Drop and recreate the data tables. Stored secrets and accounts are kept."""
    path = resolve_db(db_path)
    if not yes:
        typer.confirm(f"This deletes all fetched data in {user or path}. Secrets and accounts are kept. Continue?",
                      abort=True)
    workspace_app(user, config_dir, db_path).db.reset()
    typer.echo("Database reset. Secrets and accounts were not touched.")


if __name__ == "__main__":
    app()
