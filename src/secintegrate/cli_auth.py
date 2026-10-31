"""`auth` sub-commands: who may sign in to the web UI."""
from __future__ import annotations

import getpass
from pathlib import Path

import typer

from .cli_common import DB_OPTION, resolve_db
from .storage.db import Database
from .web.auth import EMAIL_RE, MIN_PASSWORD_LENGTH, hash_password

auth_app = typer.Typer(help="Manage who can sign in to the web UI.", no_args_is_help=True)


def _email(value: str) -> str:
    email = value.strip().lower()
    if not EMAIL_RE.match(email):
        typer.echo("That does not look like an email address.")
        raise typer.Exit(1)
    return email


@auth_app.command("add")
def auth_add(email: str = typer.Argument(..., help="Google account to allow."),
             db_path: Path | None = DB_OPTION) -> None:
    """Allow a Google account to sign in. Google sign-in also needs GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."""
    address = _email(email)
    Database(resolve_db(db_path)).add_app_user(address)
    typer.echo(f"{address} may now sign in with Google.")


@auth_app.command("set-password")
def auth_set_password(email: str = typer.Argument(..., help="Account to create or update."),
                      db_path: Path | None = DB_OPTION) -> None:
    """Create a password login (a fallback when Google is not set up). The password is typed at a hidden prompt."""
    address = _email(email)
    first = getpass.getpass(f"New password for {address} (hidden): ")
    if len(first) < MIN_PASSWORD_LENGTH:
        typer.echo(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
        raise typer.Exit(1)
    if first != getpass.getpass("Type it again to confirm (hidden): "):
        typer.echo("The two entries did not match. Nothing was changed.")
        raise typer.Exit(1)
    Database(resolve_db(db_path)).set_app_password(address, hash_password(first))
    typer.echo(f"Password set for {address}.")


@auth_app.command("approve")
def auth_approve(email: str = typer.Argument(..., help="A pending account to approve."),
                 db_path: Path | None = DB_OPTION) -> None:
    """Approve someone who created an account on the sign-in page."""
    address = _email(email)
    if not Database(resolve_db(db_path)).approve_app_user(address):
        typer.echo(f"{address} has no pending request.")
        raise typer.Exit(1)
    typer.echo(f"{address} can now sign in.")


@auth_app.command("list")
def auth_list(db_path: Path | None = DB_OPTION) -> None:
    """List who may sign in. Passwords are never shown."""
    users = Database(resolve_db(db_path)).list_app_users()
    if not users:
        typer.echo("Nobody can sign in yet. Run `hermes auth set-password you@example.com` "
                   "or `hermes auth add you@gmail.com`.")
        return
    for user in users:
        how = "google + password" if user["has_password"] else "google only"
        typer.echo(f"{user['email']:<32} {user['status']:<8} {how:<18} added {user['added_at']}")


@auth_app.command("remove")
def auth_remove(email: str = typer.Argument(..., help="Account to remove."),
                db_path: Path | None = DB_OPTION) -> None:
    """Remove someone's access."""
    address = _email(email)
    if not Database(resolve_db(db_path)).remove_app_user(address):
        typer.echo(f"{address} was not on the list.")
        raise typer.Exit(1)
    typer.echo(f"Removed {address}. They are signed out on their next click.")
