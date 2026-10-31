"""`secret` sub-commands: set, list, delete, import-env (Feature A, section 1.4 and 1.5)."""
from __future__ import annotations

import getpass
from pathlib import Path

import typer
import yaml
from dotenv import dotenv_values
from pydantic import ValidationError

from .bootstrap import App, build_app
from .cli_common import CONFIG_DIR, DB_OPTION, friendly_errors, resolve_db
from .config.loader import config_files, parse_config
from .health import refresh_connection
from .security.factory import build_vault
from .security.vault import NAME_RE, check_name

secret_app = typer.Typer(help="Manage encrypted secrets.", no_args_is_help=True)


@secret_app.command("set")
@friendly_errors
def secret_set(
    name: str = typer.Argument(..., help="Secret name, for example GITHUB_TOKEN."),
    db_path: Path | None = DB_OPTION,
    config_dir: Path = CONFIG_DIR,
) -> None:
    """Store a secret. The value is typed at a hidden prompt, never passed as an argument."""
    check_name(name)
    first = getpass.getpass(f"Value for {name} (hidden): ")
    second = getpass.getpass("Type it again to confirm (hidden): ")
    if first != second:
        typer.echo("The two entries did not match. Nothing was stored.")
        raise typer.Exit(1)
    ctx = build_app(config_dir, resolve_db(db_path))
    ctx.vault.store(name, first)
    typer.echo(f"Stored {name} (encrypted).")
    for connector in _resume_using(ctx, name):
        typer.echo(f"Resumed {connector}.")


def _resume_using(ctx: App, name: str) -> list[str]:
    """A new value for a secret un-pauses the connectors that were paused because it was rejected."""
    resumed: list[str] = []
    for file in config_files(ctx.config_dir):
        try:
            cfg = parse_config(file)
        except (ValidationError, yaml.YAMLError):
            continue
        conn = ctx.db.get_connection(cfg.connector)
        if conn and conn["paused"] and name in (cfg.auth.secret, cfg.auth.username_env):
            refresh_connection(ctx.db, ctx.notifier, cfg.connector, paused=0, consecutive_failures=0, message=None)
            resumed.append(cfg.connector)
    return resumed


@secret_app.command("list")
@friendly_errors
def secret_list(db_path: Path | None = DB_OPTION) -> None:
    """List secret names and when they were last updated. Values are never shown."""
    entries = build_vault(resolve_db(db_path)).entries()
    if not entries:
        typer.echo("No secrets stored. Add one with `secintegrate secret set NAME`.")
        return
    width = max(len(n) for n, _ in entries)
    for name, updated in entries:
        typer.echo(f"{name:<{width}}  updated {updated}")


@secret_app.command("delete")
@friendly_errors
def secret_delete(
    name: str = typer.Argument(..., help="Secret name."),
    db_path: Path | None = DB_OPTION,
) -> None:
    """Delete a stored secret after confirmation."""
    check_name(name)
    typer.confirm(f"Delete secret {name}?", abort=True)
    build_vault(resolve_db(db_path)).delete(name)
    typer.echo(f"Deleted {name}.")


@secret_app.command("import-env")
@friendly_errors
def secret_import_env(
    path: Path = typer.Argument(..., help="A .env file to import from."),
    db_path: Path | None = DB_OPTION,
) -> None:
    """One-time import of a plaintext .env file into the encrypted store."""
    vault = build_vault(resolve_db(db_path))
    imported: list[str] = []
    for key, value in sorted(dotenv_values(path).items()):
        if value and NAME_RE.match(key):
            vault.store(key, value)
            imported.append(key)
    typer.echo("Imported: " + (", ".join(imported) if imported else "nothing"))
    typer.echo("The file was NOT deleted. Delete it, and rotate these keys at the provider.")
