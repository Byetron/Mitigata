"""Options and helpers shared by CLI modules."""
from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import typer

from .security.errors import SecIntegrateError
from .security.factory import default_db_path

F = TypeVar("F", bound=Callable[..., Any])

CONFIG_DIR = typer.Option(Path("config/connectors"), "--config-dir", "-c", help="Connector YAML directory.")
DB_OPTION = typer.Option(None, "--db", help="SQLite file (default: per-user data directory).")


def resolve_db(db: Path | None) -> Path:
    return db if db is not None else default_db_path()


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
