"""Command line interface (spec 7.1 and brief 1.4, 3.5)."""
from __future__ import annotations

import logging
from pathlib import Path

import typer

from .bootstrap import App, build_app
from .cli_common import CONFIG_DIR, DB_OPTION, friendly_errors, resolve_db
from .cli_secrets import secret_app
from .config.loader import config_files, find_connector_file, parse_config
from .config.schema import ConnectorConfig
from .config.validator import has_errors, validate_dir, validate_paths
from .health import refresh_connection
from .logging_utils import setup_logging

app = typer.Typer(help="Hermes: config-driven security integration platform.", no_args_is_help=True)
db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
app.add_typer(db_app, name="db")
app.add_typer(secret_app, name="secret")


def _app(config_dir: Path, db_path: Path | None) -> App:
    return build_app(config_dir, resolve_db(db_path))


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

    ctx = _app(config_dir, db_path)
    ctx.vault.init_key()
    for cfg in _valid_configs(ctx):
        ctx.db.ensure_connection(cfg.connector)
    jobs = len(build_scheduler(_valid_configs(ctx), ctx).get_jobs())
    typer.echo(f"Hermes is ready. Data is stored in: {resolve_db(db_path)}")
    typer.echo(f"{jobs} scheduled job(s) (runs and probes) are configured.")
    typer.echo("The master key is held by the OS keychain (or SECINTEGRATE_MASTER_KEY). It is never printed.")


@app.command()
@friendly_errors
def validate(path: Path = typer.Argument(None, help="A file or directory (default: config dir)."),
             config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION) -> None:
    """Validate connector configs. Exit 1 if any have errors (warnings do not fail)."""
    target = path or config_dir
    secrets = _app(config_dir, db_path).vault.list_names()
    if target.is_file():
        issues, count = validate_paths([target], secrets), 1
    else:
        issues, count = validate_dir(target, secrets), len(config_files(target))
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
        config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION) -> None:
    """Run one connector now."""
    from .runner import run_connector

    del once  # accepted for compatibility: a run is always one pass
    setup_logging("logs")
    ctx = _app(config_dir, db_path)
    file = find_connector_file(config_dir, connector)
    if file is None:
        typer.echo(f"No connector '{connector}' found in {config_dir}.")
        raise typer.Exit(2)
    issues = [i for i in validate_dir(config_dir, ctx.vault.list_names()) if Path(i.file) == file]
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
@friendly_errors
def resume(connector: str = typer.Argument(..., help="Connector id to resume."),
           config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION) -> None:
    """Un-pause a connector that was paused after repeated auth failures."""
    ctx = _app(config_dir, db_path)
    if ctx.db.get_connection(connector) is None:
        typer.echo(f"No connector '{connector}' has run yet.")
        raise typer.Exit(2)
    refresh_connection(ctx.db, ctx.notifier, connector, paused=0, consecutive_failures=0, message=None)
    typer.echo(f"Resumed {connector}.")


@app.command()
@friendly_errors
def serve(port: int = typer.Option(8000, "--port"), config_dir: Path = CONFIG_DIR,
          db_path: Path | None = DB_OPTION) -> None:
    """Start the scheduler and the web server (127.0.0.1 only)."""
    from .scheduler import build_scheduler
    from .web.app import create_app

    setup_logging("logs")
    log = logging.getLogger("secintegrate")
    ctx = _app(config_dir, db_path)
    configs = _valid_configs(ctx)
    for cfg in configs:
        ctx.db.ensure_connection(cfg.connector)
    sched = build_scheduler(configs, ctx)
    sched.start()
    log.info("scheduled %d connector(s); dashboard at http://127.0.0.1:%d/", sum(c.enabled for c in configs), port)
    try:
        create_app(config_dir, ctx.db, ctx.vault.list_names).run(host="127.0.0.1", port=port, use_reloader=False)
    finally:
        sched.shutdown(wait=False)


@app.command()
@friendly_errors
def status(config_dir: Path = CONFIG_DIR, db_path: Path | None = DB_OPTION) -> None:
    """Print the health table."""
    from .web.app import _register_connections

    ctx = _app(config_dir, db_path)
    _register_connections(config_dir, ctx.db)
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
def db_reset(db_path: Path | None = DB_OPTION,
             yes: bool = typer.Option(False, "--yes", help="Skip confirmation.")) -> None:
    """Drop and recreate the data tables. Stored secrets are kept."""
    path = resolve_db(db_path)
    if not yes:
        typer.confirm(f"This deletes all fetched data in {path}. Secrets are kept. Continue?", abort=True)
    _app(Path("config/connectors"), path).db.reset()
    typer.echo("Database reset. Secrets were not touched.")


if __name__ == "__main__":
    app()
