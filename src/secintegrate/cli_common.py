"""Options and helpers shared by CLI modules."""
from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import typer

from .bootstrap import App, build_app
from .security.errors import SecIntegrateError
from .security.factory import default_db_path
from .storage.db import Database
from .workspaces import WorkspaceManager

F = TypeVar("F", bound=Callable[..., Any])

CONFIG_DIR = typer.Option(Path("config/connectors"), "--config-dir", "-c", help="Connector YAML directory.")
DB_OPTION = typer.Option(None, "--db", help="SQLite file (default: per-user data directory).")
USER_OPTION = typer.Option(None, "--user", "-u", help="Work on this account's own connectors and keys.")


def resolve_db(db: Path | None) -> Path:
    return db if db is not None else default_db_path()


def workspace_app(user: str | None, config_dir: Path, db_path: Path | None) -> App:
    """The workspace a command works on: the default one, or the named account's own."""
    path = resolve_db(db_path)
    if user is None:
        return build_app(config_dir, path)
    system = Database(path)
    if system.get_app_user(user) is None:
        typer.echo(f"There is no account for {user}. See `hermes auth list`.")
        raise typer.Exit(2)
    return WorkspaceManager(system, config_dir, path).app_for(user)


def friendly_errors(func: F) -> F:
    """Show platform errors as one clean line instead of a traceback."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except SecIntegrateError as exc:
            typer.echo(f"Error: {exc}")
            raise typer.Exit(1) from exc

    return wrapper  # type: ignore[return-value]
