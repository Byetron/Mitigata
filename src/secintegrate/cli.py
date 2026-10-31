"""Command line interface (spec 7.1)."""
from __future__ import annotations

import logging
from pathlib import Path

import typer
from dotenv import load_dotenv

from .config.loader import config_files, find_connector_file, parse_config
from .config.validator import validate_dir, validate_paths
from .logging_utils import setup_logging
from .storage.db import Database

app = typer.Typer(help="Config-driven security integration platform.", no_args_is_help=True)
db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
app.add_typer(db_app, name="db")

CONFIG_DIR = typer.Option("config/connectors", "--config-dir", "-c", help="Connector YAML directory.")
DB_PATH = typer.Option("data/secintegrate.db", "--db", help="SQLite file.")


def _boot() -> None:
    load_dotenv(Path(".env"))
    setup_logging("logs")


@app.command()
def validate(path: Path = typer.Argument(None, help="A file or directory (default: config dir)."),
             config_dir: Path = CONFIG_DIR) -> None:
    """Validate connector configs. Exit 1 if any are invalid."""
    load_dotenv(Path(".env"))
    target = path or config_dir
    if target.is_file():
        issues, count = validate_paths([target]), 1
    else:
        issues, count = validate_dir(target), len(config_files(target))
    for issue in issues:
        typer.echo(str(issue))
    if issues:
        typer.echo(f"{len(issues)} problem(s) found.")
        raise typer.Exit(1)
    typer.echo(f"OK: {count} config file(s) valid.")


@app.command()
def run(connector: str = typer.Argument(..., help="Connector id."),
        once: bool = typer.Option(True, "--once", help="Run once now (default)."),
        no_throttle: bool = typer.Option(False, "--no-throttle", help="Disable the client-side rate limit."),
        config_dir: Path = CONFIG_DIR, db_path: Path = DB_PATH) -> None:
    """Run one connector now."""
    from .runner import run_connector

    _boot()
    file = find_connector_file(config_dir, connector)
    if file is None:
        typer.echo(f"No connector '{connector}' found in {config_dir}.")
        raise typer.Exit(2)
    issues = [i for i in validate_dir(config_dir) if Path(i.file) == file]
    if issues:
        for i in issues:
            typer.echo(str(i))
        typer.echo("Refusing to run an invalid config.")
        raise typer.Exit(1)
    result = run_connector(parse_config(file), Database(db_path), throttle=not no_throttle)
    typer.echo(result.summary)
    typer.echo(f"pages={result.pages} requests={result.requests} records_ok={result.records_ok} "
               f"records_bad={result.records_bad} seconds={result.seconds:.1f}")
    if result.status == "failed":
        raise typer.Exit(1)


@app.command()
def serve(port: int = typer.Option(8000, "--port"), config_dir: Path = CONFIG_DIR,
          db_path: Path = DB_PATH) -> None:
    """Start the scheduler and the web server."""
    from .scheduler import build_scheduler
    from .web.app import create_app

    _boot()
    log = logging.getLogger("secintegrate")
    db = Database(db_path)
    bad_files = {Path(i.file) for i in validate_dir(config_dir, check_env=False)}
    configs = []
    for f in config_files(config_dir):
        if f in bad_files:
            log.warning("skipping %s: invalid config (run 'secintegrate validate')", f)
            continue
        cfg = parse_config(f)
        db.ensure_connection(cfg.connector)
        configs.append(cfg)
    sched = build_scheduler(configs, db)
    sched.start()
    log.info("scheduled %d connector(s); health page at http://localhost:%d/health",
             sum(c.enabled for c in configs), port)
    try:
        create_app(config_dir, db).run(host="127.0.0.1", port=port, use_reloader=False)
    finally:
        sched.shutdown(wait=False)


@app.command()
def status(config_dir: Path = CONFIG_DIR, db_path: Path = DB_PATH) -> None:
    """Print the health table."""
    from .web.app import _register_connections

    load_dotenv(Path(".env"))
    db = Database(db_path)
    _register_connections(config_dir, db)
    rows = db.health_rows()
    head = f"{'connector':<20}{'status':<10}{'last run':<22}{'pulled':>7}{'bad':>5}{'fails':>6}  last error"
    typer.echo(head)
    typer.echo("-" * len(head))
    for r in rows:
        bad = "-" if r["last_bad"] is None else r["last_bad"]
        typer.echo(f"{r['connector']:<20}{r['status']:<10}{(r['last_run_finished_at'] or '-'):<22}"
                   f"{r['last_records_pulled'] or 0:>7}{bad:>5}{r['consecutive_failures'] or 0:>6}  "
                   f"{r['last_error'] or ''}")


@db_app.command("reset")
def db_reset(db_path: Path = DB_PATH, yes: bool = typer.Option(False, "--yes", help="Skip confirmation.")) -> None:
    """Drop and recreate all tables."""
    if not yes:
        typer.confirm(f"This deletes all data in {db_path}. Continue?", abort=True)
    Database(db_path).reset()
    typer.echo("Database reset.")


if __name__ == "__main__":
    app()
