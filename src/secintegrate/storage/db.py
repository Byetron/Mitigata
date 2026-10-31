"""SQLite storage: common-schema upserts, runs, probes, quarantine, sync state (FR-11)."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..secrets import redact

TABLES = {
    "user": ("users", ["name", "email", "status", "last_login"]),
    "device": ("devices", ["hostname", "ip", "os", "owner", "last_seen"]),
    "event": ("events", ["type", "severity", "timestamp", "description"]),
}
# The `secrets` table is deliberately NOT here: resetting data must never destroy stored keys.
ALL_TABLES = ["users", "devices", "events", "connections", "runs", "quarantine", "sync_state", "probes"]
CONNECTION_COLUMNS = {
    "status", "last_run_started_at", "last_run_finished_at", "last_records_pulled", "last_error",
    "consecutive_failures", "paused", "last_category", "message",
}
_ADDED_COLUMNS = {"paused": "INTEGER DEFAULT 0", "last_category": "TEXT", "message": "TEXT"}
PROBE_RETENTION_DAYS = 30


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def init(self) -> None:
        schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
        with self.conn() as c:
            c.executescript(schema)
            have = {row["name"] for row in c.execute("PRAGMA table_info(connections)")}
            for column, ddl in _ADDED_COLUMNS.items():  # migrate databases created by older versions
                if column not in have:
                    c.execute(f"ALTER TABLE connections ADD COLUMN {column} {ddl}")
            user_cols = {row["name"] for row in c.execute("PRAGMA table_info(app_users)")}
            if "status" not in user_cols:
                c.execute("ALTER TABLE app_users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            c.execute("UPDATE app_users SET status='active' WHERE status != 'active'")  # approval was removed

    def reset(self) -> None:
        with self.conn() as c:
            for t in ALL_TABLES:
                c.execute(f"DROP TABLE IF EXISTS {t}")
        self.init()

    # --- common schema -------------------------------------------------
    def upsert(self, target: str, source: str, rows: list[dict[str, Any]], fetched_at: str) -> None:
        if not rows:
            return
        table, cols = TABLES[target]
        names = ["source", "id", *cols, "fetched_at"]
        updates = ", ".join(f"{c}=excluded.{c}" for c in [*cols, "fetched_at"])
        sql = (
            f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))}) "  # noqa: S608
            f"ON CONFLICT(source, id) DO UPDATE SET {updates}"
        )
        data = [(source, str(r["id"]), *[r.get(c) for c in cols], fetched_at) for r in rows]
        with self.conn() as c:
            c.executemany(sql, data)

    # --- runs ------------------------------------------------------------
    def start_run(self, connector: str, started_at: str) -> int:
        with self.conn() as c:
            cur = c.execute(
                "INSERT INTO runs (connector, started_at, status) VALUES (?, ?, 'running')",
                (connector, started_at),
            )
            return int(cur.lastrowid or 0)

    def finish_run(self, run_id: int, status: str, ok: int, bad: int, error: str | None) -> None:
        with self.conn() as c:
            c.execute(
                "UPDATE runs SET finished_at=?, status=?, records_ok=?, records_bad=?, error=? WHERE id=?",
                (now_iso(), status, ok, bad, redact(error) if error else None, run_id),
            )

    def latest_run(self, connector: str) -> dict[str, Any] | None:
        with self.conn() as c:
            row = c.execute(
                "SELECT * FROM runs WHERE connector=? AND status != 'running' ORDER BY id DESC LIMIT 1",
                (connector,),
            ).fetchone()
        return dict(row) if row else None

    def last_success(self, connector: str) -> str | None:
        """When this connector last finished a run that stored data (success or partial)."""
        with self.conn() as c:
            row = c.execute(
                "SELECT MAX(finished_at) FROM runs WHERE connector=? AND status IN ('success', 'partial')",
                (connector,),
            ).fetchone()
        return str(row[0]) if row and row[0] else None

    def add_quarantine(self, run_id: int, connector: str, endpoint: str, index: int, reason: str, raw: Any) -> bool:
        """Store a bad record. An identical record already waiting is not stored twice. Returns True if new."""
        try:
            raw_json = redact(json.dumps(raw, default=str))
        except (TypeError, ValueError):
            raw_json = redact(repr(raw))
        with self.conn() as c:
            if c.execute(
                "SELECT 1 FROM quarantine WHERE connector=? AND endpoint=? AND reason=? AND raw_json=? LIMIT 1",
                (connector, endpoint, reason, raw_json),
            ).fetchone():
                return False
            c.execute(
                "INSERT INTO quarantine (run_id, connector, endpoint, record_index, reason, raw_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (run_id, connector, endpoint, index, reason, raw_json, now_iso()),
            )
        return True

    def quarantined(self, connector: str, limit: int = 500) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT id, endpoint, raw_json FROM quarantine WHERE connector=? ORDER BY id LIMIT ?",
                (connector, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_quarantine(self, row_id: int) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM quarantine WHERE id=?", (row_id,))

    def delete_connector_state(self, connector: str) -> None:
        """Forget a removed connector's health, history, probes and cursor. Fetched records are kept."""
        with self.conn() as c:
            for table in ("connections", "runs", "quarantine", "sync_state", "probes"):
                c.execute(f"DELETE FROM {table} WHERE connector=?", (connector,))  # noqa: S608

    # --- probes ----------------------------------------------------------
    def add_probe(self, connector: str, ok: bool, category: str | None, http_status: int | None,
                  latency_ms: int | None) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=PROBE_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.conn() as c:
            c.execute(
                "INSERT INTO probes (connector, checked_at, ok, category, http_status, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (connector, now_iso(), int(ok), category, http_status, latency_ms),
            )
            c.execute("DELETE FROM probes WHERE checked_at < ?", (cutoff,))  # prune on each write

    def latest_probe(self, connector: str) -> dict[str, Any] | None:
        with self.conn() as c:
            row = c.execute(
                "SELECT * FROM probes WHERE connector=? ORDER BY id DESC LIMIT 1", (connector,)
            ).fetchone()
        return dict(row) if row else None

    def recent_probes(self, connector: str, limit: int = 24) -> list[dict[str, Any]]:
        """Oldest first, so a sparkline reads left to right."""
        with self.conn() as c:
            rows = c.execute(
                "SELECT ok, category, checked_at FROM probes WHERE connector=? ORDER BY id DESC LIMIT ?",
                (connector, limit),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def count_rows(self, table: str, connector: str) -> int:
        if table not in ("probes", "runs", "quarantine"):
            raise ValueError(table)
        with self.conn() as c:
            return int(c.execute(f"SELECT COUNT(*) FROM {table} WHERE connector=?", (connector,)).fetchone()[0])  # noqa: S608

    # --- incremental state -------------------------------------------------
    def get_cursor(self, connector: str, endpoint: str) -> str | None:
        with self.conn() as c:
            row = c.execute(
                "SELECT cursor FROM sync_state WHERE connector=? AND endpoint=?", (connector, endpoint)
            ).fetchone()
        return str(row["cursor"]) if row and row["cursor"] is not None else None

    def set_cursor(self, connector: str, endpoint: str, cursor: str) -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO sync_state (connector, endpoint, cursor, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(connector, endpoint) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at",
                (connector, endpoint, cursor, now_iso()),
            )

    # --- health ------------------------------------------------------------
    def ensure_connection(self, connector: str) -> None:
        with self.conn() as c:
            c.execute("INSERT OR IGNORE INTO connections (connector, status) VALUES (?, 'never_run')", (connector,))

    def get_connection(self, connector: str) -> dict[str, Any] | None:
        with self.conn() as c:
            row = c.execute("SELECT * FROM connections WHERE connector=?", (connector,)).fetchone()
        return dict(row) if row else None

    def update_connection(self, connector: str, **fields: Any) -> None:
        unknown = set(fields) - CONNECTION_COLUMNS
        if unknown:
            raise ValueError(f"unknown connection columns: {sorted(unknown)}")
        for key in ("last_error", "message"):
            if fields.get(key):
                fields[key] = redact(str(fields[key]))
        self.ensure_connection(connector)
        if not fields:
            return
        assignments = ", ".join(f"{k}=?" for k in fields)
        with self.conn() as c:
            c.execute(f"UPDATE connections SET {assignments} WHERE connector=?", (*fields.values(), connector))  # noqa: S608

    def set_paused(self, connector: str, paused: bool) -> None:
        extra: dict[str, Any] = {} if paused else {"consecutive_failures": 0}
        self.update_connection(connector, paused=int(paused), **extra)

    def health_rows(self) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT c.*, (SELECT r.records_bad FROM runs r WHERE r.connector = c.connector "
                "ORDER BY r.id DESC LIMIT 1) AS last_bad FROM connections c ORDER BY c.connector"
            ).fetchall()
        return [dict(r) for r in rows]

    def dashboard(self, source: str | None = None) -> dict[str, Any]:
        """Non-sensitive aggregates for the home page (no emails, no raw records, no secrets).

        `source` filters the recent-events list to one connector's source.
        """
        with self.conn() as c:
            def rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
                return [dict(r) for r in c.execute(sql, params).fetchall()]

            def one(sql: str) -> int:
                return int(c.execute(sql).fetchone()[0])

            where = "WHERE source = ? " if source else ""
            return {
                "totals": {
                    "events": one("SELECT COUNT(*) FROM events"),
                    "devices": one("SELECT COUNT(*) FROM devices"),
                    "users": one("SELECT COUNT(*) FROM users"),
                    "quarantined": one("SELECT COUNT(*) FROM quarantine"),
                },
                "event_sources": rows("SELECT source, COUNT(*) AS n FROM events GROUP BY source ORDER BY source"),
                "recent_events": rows(
                    "SELECT source, id, type, severity, timestamp, description FROM events "  # noqa: S608
                    + where + "ORDER BY timestamp DESC LIMIT 10",
                    (source,) if source else (),
                ),
                "recent_devices": rows(
                    "SELECT source, id, os, owner, last_seen FROM devices ORDER BY last_seen DESC LIMIT 5"),
            }

    # --- people who may sign in to the web UI ----------------------------------
    # The `app_users` table is not in ALL_TABLES, so `db reset` never locks you out.
    def add_app_user(self, email: str) -> None:
        """Allow an address (an administrator action), keeping any existing password."""
        with self.conn() as c:
            c.execute("INSERT OR IGNORE INTO app_users (email, added_at, status) VALUES (?, ?, 'active')",
                      (email.lower(), now_iso()))
            c.execute("UPDATE app_users SET status='active' WHERE email=?", (email.lower(),))

    def set_app_password(self, email: str, password_hash: str) -> None:
        """Administrator action: set a password and make sure the account is active."""
        self.add_app_user(email)
        with self.conn() as c:
            c.execute("UPDATE app_users SET password_hash=? WHERE email=?", (password_hash, email.lower()))

    def create_app_user(self, email: str, password_hash: str | None) -> str:
        """Self-service sign-up. Returns "created" or "exists". An existing address is never changed."""
        with self.conn() as c:
            added = c.execute(
                "INSERT OR IGNORE INTO app_users (email, password_hash, added_at, status) VALUES (?, ?, ?, 'active')",
                (email.lower(), password_hash, now_iso()),
            ).rowcount
        return "created" if added else "exists"

    def get_app_user(self, email: str) -> dict[str, Any] | None:
        with self.conn() as c:
            row = c.execute("SELECT * FROM app_users WHERE email=?", (email.lower(),)).fetchone()
        return dict(row) if row else None

    def list_app_users(self) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute("SELECT email, password_hash IS NOT NULL AS has_password, added_at "
                             "FROM app_users ORDER BY added_at, email").fetchall()
        return [dict(r) for r in rows]

    def get_setting(self, key: str) -> str | None:
        with self.conn() as c:
            row = c.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO app_settings (key, value) VALUES (?, ?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def remove_app_user(self, email: str) -> bool:
        with self.conn() as c:
            return c.execute("DELETE FROM app_users WHERE email=?", (email.lower(),)).rowcount > 0

    def count(self, table: str) -> int:
        if table not in ALL_TABLES:
            raise ValueError(table)
        with self.conn() as c:
            return int(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608
