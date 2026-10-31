"""SQLite storage: common-schema upserts, runs, quarantine, sync state (FR-11)."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..secrets import redact

TABLES = {
    "user": ("users", ["name", "email", "status", "last_login"]),
    "device": ("devices", ["hostname", "ip", "os", "owner", "last_seen"]),
    "event": ("events", ["type", "severity", "timestamp", "description"]),
}
ALL_TABLES = ["users", "devices", "events", "connections", "runs", "quarantine", "sync_state"]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    def __init__(self, path: str | Path):
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
            f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))}) "
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
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, ok: int, bad: int, error: str | None) -> None:
        with self.conn() as c:
            c.execute(
                "UPDATE runs SET finished_at=?, status=?, records_ok=?, records_bad=?, error=? WHERE id=?",
                (now_iso(), status, ok, bad, redact(error) if error else None, run_id),
            )

    def add_quarantine(self, run_id: int, connector: str, endpoint: str, index: int, reason: str, raw: Any) -> None:
        try:
            raw_json = redact(json.dumps(raw, default=str))
        except (TypeError, ValueError):
            raw_json = redact(repr(raw))
        with self.conn() as c:
            c.execute(
                "INSERT INTO quarantine (run_id, connector, endpoint, record_index, reason, raw_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (run_id, connector, endpoint, index, reason, raw_json, now_iso()),
            )

    # --- incremental state -------------------------------------------------
    def get_cursor(self, connector: str, endpoint: str) -> str | None:
        with self.conn() as c:
            row = c.execute(
                "SELECT cursor FROM sync_state WHERE connector=? AND endpoint=?", (connector, endpoint)
            ).fetchone()
        return row["cursor"] if row else None

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
            c.execute(
                "INSERT OR IGNORE INTO connections (connector, status) VALUES (?, 'never_run')", (connector,)
            )

    def get_connection(self, connector: str) -> sqlite3.Row | None:
        with self.conn() as c:
            return c.execute("SELECT * FROM connections WHERE connector=?", (connector,)).fetchone()

    def update_connection(
        self, connector: str, status: str, started: str, finished: str, records: int,
        error: str | None, failures: int,
    ) -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO connections (connector, status, last_run_started_at, last_run_finished_at, "
                "last_records_pulled, last_error, consecutive_failures) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(connector) DO UPDATE SET status=excluded.status, "
                "last_run_started_at=excluded.last_run_started_at, last_run_finished_at=excluded.last_run_finished_at, "
                "last_records_pulled=excluded.last_records_pulled, last_error=excluded.last_error, "
                "consecutive_failures=excluded.consecutive_failures",
                (connector, status, started, finished, records, redact(error) if error else None, failures),
            )

    def health_rows(self) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT c.*, (SELECT r.records_bad FROM runs r WHERE r.connector = c.connector "
                "ORDER BY r.id DESC LIMIT 1) AS last_bad FROM connections c ORDER BY c.connector"
            ).fetchall()
        return [dict(r) for r in rows]

    def dashboard(self) -> dict[str, Any]:
        """Non-sensitive aggregates for the home page (no emails, no raw records, no secrets)."""
        with self.conn() as c:
            def rows(sql: str) -> list[dict[str, Any]]:
                return [dict(r) for r in c.execute(sql).fetchall()]

            def one(sql: str) -> int:
                return int(c.execute(sql).fetchone()[0])

            return {
                "totals": {
                    "events": one("SELECT COUNT(*) FROM events"),
                    "devices": one("SELECT COUNT(*) FROM devices"),
                    "users": one("SELECT COUNT(*) FROM users"),
                    "quarantined": one("SELECT COUNT(*) FROM quarantine"),
                },
                "recent_events": rows(
                    "SELECT source, id, type, severity, timestamp, description FROM events "
                    "ORDER BY timestamp DESC LIMIT 8"),
                "recent_devices": rows(
                    "SELECT source, id, os, owner, last_seen FROM devices ORDER BY last_seen DESC LIMIT 5"),
            }

    def count(self, table: str) -> int:
        if table not in ALL_TABLES:
            raise ValueError(table)
        with self.conn() as c:
            return int(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
