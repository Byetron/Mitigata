"""SQLite storage for encrypted secrets. Only ciphertext ever reaches this module."""
from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from .errors import SecretNotFoundError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    name        TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    updated_at  TEXT NOT NULL
)
"""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class SqliteSecretRepository:
    """`db_path` may be ":memory:" (one connection is kept open, so the data survives between calls)."""

    def __init__(self, db_path: str | Path) -> None:
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
        with self._lock:
            self._conn.execute(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def put(self, name: str, blob: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO secrets (name, ciphertext, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext, updated_at=excluded.updated_at",
                (name, blob, _now()),
            )
            self._conn.commit()

    def get(self, name: str) -> bytes:
        with self._lock:
            row = self._conn.execute("SELECT ciphertext FROM secrets WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise SecretNotFoundError(name)
        return bytes(row[0])

    def delete(self, name: str) -> None:
        with self._lock:
            cur = self._conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
            self._conn.commit()
        if cur.rowcount == 0:
            raise SecretNotFoundError(name)

    def names(self) -> list[str]:
        return [name for name, _ in self.entries()]

    def entries(self) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute("SELECT name, updated_at FROM secrets ORDER BY name").fetchall()
        return [(str(r[0]), str(r[1])) for r in rows]
