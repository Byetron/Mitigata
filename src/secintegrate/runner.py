"""Execute one connector run end to end (spec 5.1)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .auth import secret_env_names
from .config.loader import expand_env
from .http.client import ApiClient
from .http.retry import FetchError
from .incremental import max_cursor, plan_requests
from .mapping import MappingError, apply_mapping, get_path
from .pagination import iter_pages
from .secrets import MissingSecret, get_secret
from .storage.db import Database, now_iso

logger = logging.getLogger(__name__)


@dataclass
class RunResult:
    connector: str
    status: str
    records_ok: int
    records_bad: int
    pages: int
    requests: int
    error: str | None
    seconds: float

    @property
    def summary(self) -> str:
        if self.status == "failed":
            return f"{self.connector}: failed. {self.error}"
        if self.status == "partial":
            total = self.records_ok + self.records_bad
            return (f"{self.connector}: {self.records_bad} of {total} records invalid, "
                    f"quarantined. Status: partial.")
        return f"{self.connector}: {self.records_ok} records, {self.pages} pages. Status: success."


def connection_status(run_status: str, error: str | None, failures: int) -> str:
    """Spec 7.3 status rules."""
    if run_status == "success":
        return "healthy"
    if run_status == "partial":
        return "degraded"
    if run_status == "failed":
        if failures >= 3 or (error or "").startswith("auth_failed"):
            return "failing"
        return "degraded"
    return "never_run"


class _EndpointState:
    def __init__(self) -> None:
        self.index = 0
        self.cursor: str | None = None


def _expand_vars(vars_: dict[str, Any]) -> dict[str, Any]:
    return {k: expand_env(v) if isinstance(v, str) else v for k, v in vars_.items()}


def _run_endpoint(cfg, ep, base: str, client: ApiClient, db: Database, run_id: int, totals: dict) -> str | None:
    try:
        path = ep.path.format(**_expand_vars(ep.vars))
    except KeyError as exc:
        raise FetchError("config_error", f"path placeholder {exc} has no value") from None
    url = base.rstrip("/") + path

    inc = ep.incremental
    plans: list[dict[str, Any]] = [{}]
    if inc:
        plans = plan_requests(inc, db.get_cursor(cfg.connector, ep.name))

    state = _EndpointState()
    target = ep.mapping.target
    for plan in plans:
        params = {**ep.params, **plan}
        for records in iter_pages(lambda u, p: client.request(ep.method, u, p), url, params,
                                  ep.pagination, ep.records_path):
            totals["pages"] += 1
            rows = []
            for rec in records:
                idx = state.index
                state.index += 1
                try:
                    row = apply_mapping(rec, ep.mapping.fields)
                    if row.get("id") in (None, ""):
                        raise MappingError("required field missing: id")
                except MappingError as exc:
                    db.add_quarantine(run_id, cfg.connector, ep.name, idx, str(exc), rec)
                    totals["bad"] += 1
                    continue
                rows.append(row)
                if inc and isinstance(rec, dict):
                    found, value = get_path(rec, inc.cursor_field)
                    if found and value is not None:
                        state.cursor = max_cursor(state.cursor, value)
            db.upsert(target, cfg.source, rows, now_iso())  # commit per page
            totals["ok"] += len(rows)
    return state.cursor


def run_connector(
    cfg,
    db: Database,
    throttle: bool = True,
    sleep: Callable[[float], None] = time.sleep,
    transport=None,
) -> RunResult:
    began = time.monotonic()
    db.ensure_connection(cfg.connector)
    started = now_iso()
    run_id = db.start_run(cfg.connector, started)
    totals = {"ok": 0, "bad": 0, "pages": 0}
    error: str | None = None
    client: ApiClient | None = None
    pending: dict[str, str] = {}

    try:
        base = expand_env(cfg.base_url)
        for name in secret_env_names(cfg.auth):
            get_secret(name)
        client = ApiClient(cfg, throttle=throttle, sleep=sleep, transport=transport)
        for ep in cfg.endpoints:
            cursor = _run_endpoint(cfg, ep, base, client, db, run_id, totals)
            if cursor:
                pending[ep.name] = cursor
        for name, cursor in pending.items():  # only after every endpoint succeeded
            db.set_cursor(cfg.connector, name, cursor)
    except MissingSecret as exc:
        error = f"config_error: env {exc} is not set"
    except FetchError as exc:
        error = f"{exc.code}: {exc.detail}"
    except Exception as exc:  # never let a bug take down the scheduler
        logger.exception("%s: unexpected error", cfg.connector)
        error = f"internal_error: {type(exc).__name__}"
    finally:
        requests = client.requests_made if client else 0
        if client:
            client.close()

    status = "failed" if error else ("partial" if totals["bad"] else "success")
    db.finish_run(run_id, status, totals["ok"], totals["bad"], error)

    prev = db.get_connection(cfg.connector)
    failures = (prev["consecutive_failures"] if prev else 0) + 1 if status == "failed" else 0
    db.update_connection(
        cfg.connector, connection_status(status, error, failures), started, now_iso(),
        totals["ok"] + totals["bad"], error, failures,
    )
    result = RunResult(cfg.connector, status, totals["ok"], totals["bad"], totals["pages"],
                       requests, error, time.monotonic() - began)
    logger.info(result.summary)
    return result
