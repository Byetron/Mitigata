"""Connection status from the latest run and probe (brief 2.5), and transition notifications."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .classify import FailureCategory
from .notify import Notifier, StateChange, should_notify
from .storage.db import Database

PAUSE_AFTER = 2


def compute_status(run_status: str | None, probe_ok: bool | None, probe_category: str | None, paused: bool) -> str:
    """healthy, degraded, failing, paused or never_run. `probe_ok` None means no probe exists."""
    if paused:
        return "paused"
    if run_status is None:
        return "never_run"
    probe_failed = probe_ok is False
    if run_status == "failed" or (probe_failed and probe_category == FailureCategory.AUTH_FAILED.value):
        return "failing"
    if run_status == "partial" or probe_failed:
        return "degraded"
    return "healthy"


def should_pause(category: FailureCategory | None, consecutive_failures: int) -> bool:
    """Auth failures pause the connector after two in a row (brief 2.4). Retrying a bad key cannot help."""
    return category is FailureCategory.AUTH_FAILED and consecutive_failures >= PAUSE_AFTER


def refresh_connection(db: Database, notifier: Notifier, connector: str, **updates: Any) -> str:
    """Apply updates, recompute the status, and notify only when the status changed in a way that matters."""
    before = db.get_connection(connector) or {}
    old_status = str(before.get("status") or "never_run")
    db.update_connection(connector, **updates)
    conn = db.get_connection(connector) or {}
    run = db.latest_run(connector)
    probe = db.latest_probe(connector)
    status = compute_status(
        run["status"] if run else None,
        bool(probe["ok"]) if probe else None,
        probe["category"] if probe else None,
        bool(conn.get("paused")),
    )
    db.update_connection(connector, status=status)
    if should_notify(old_status, status):
        message = str(conn.get("message") or "") or (
            "Connection recovered." if status == "healthy" else f"Status changed to {status}.")
        notifier.notify(StateChange(connector, old_status, status, message,
                                    datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")))
    return status
