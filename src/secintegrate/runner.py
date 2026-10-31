"""Execute one connector run end to end.

Order (brief X-2): the caller validates, then: load secret, probe if due, sync, classify failures,
apply remediation, update health, notify on a state transition.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from .auth import secret_env_names
from .autoheal import reprocess_quarantine, retry_delay_minutes
from .classify import FailureCategory, classify_exception
from .config.schema import ConnectorConfig, Endpoint
from .health import refresh_connection, should_pause
from .http.client import ApiClient
from .http.retry import FetchError
from .incremental import max_cursor, plan_requests
from .mapping import MappingError, apply_mapping, get_path
from .notify import Notifier
from .pagination import iter_pages
from .probe import probe_connector, probe_due
from .remediate import MessageContext, human_message
from .security.errors import SecIntegrateError, SecretNotFoundError
from .security.vault import SecretVault
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
    category: FailureCategory | None = None
    message: str | None = None
    retry_in_minutes: int | None = None
    resolved: int = 0

    @property
    def summary(self) -> str:
        if self.status == "paused":
            return f"{self.connector}: paused. {self.message or ''}".strip()
        if self.status == "failed":
            return f"{self.connector}: failed. {self.error}"
        if self.status == "partial":
            total = self.records_ok + self.records_bad
            return f"{self.connector}: {self.records_bad} of {total} records invalid, quarantined. Status: partial."
        return f"{self.connector}: {self.records_ok} records, {self.pages} pages. Status: success."


class _EndpointState:
    def __init__(self) -> None:
        self.index = 0
        self.cursor: str | None = None


QUARANTINE_CAP = 5000  # per connector: a broken source must not fill the disk


def _quarantine(db: Database, run_id: int, cfg: ConnectorConfig, ep: Endpoint,
                bad: list[tuple[int, Any, MappingError]], totals: dict[str, int]) -> None:
    room = max(0, QUARANTINE_CAP - db.count_rows("quarantine", cfg.connector))
    for index, record, exc in bad[:room]:
        db.add_quarantine(run_id, cfg.connector, ep.name, index, str(exc), record)
    if len(bad) > room:
        logger.warning("%s: quarantine is full (%d); %d bad record(s) counted but not stored",
                       cfg.connector, QUARANTINE_CAP, len(bad) - room)
    totals["bad"] += len(bad)


def _process_page(cfg: ConnectorConfig, ep: Endpoint, records: list[Any], state: _EndpointState,
                  db: Database, run_id: int, totals: dict[str, int]) -> None:
    good: list[dict[str, Any]] = []
    bad: list[tuple[int, Any, MappingError]] = []
    for rec in records:
        idx = state.index
        state.index += 1
        try:
            row = apply_mapping(rec, ep.mapping.fields)
            if row.get("id") in (None, ""):
                raise MappingError("required field missing: id", field="id", required_missing=True)
        except MappingError as exc:
            bad.append((idx, rec, exc))
            continue
        good.append(row)
        inc = ep.incremental
        if inc and isinstance(rec, dict):
            found, value = get_path(rec, inc.cursor_field)
            if found and value is not None:
                state.cursor = max_cursor(state.cursor, value)

    # Every record on a page lacking a required field means the API changed, not that data is bad.
    if len(records) >= 2 and len(bad) == len(records) and all(e.required_missing for _, _, e in bad):  # noqa: PLR2004
        _quarantine(db, run_id, cfg, ep, bad, totals)
        raise FetchError(FailureCategory.SCHEMA_CHANGED, "required field missing from every record on a page",
                         field=bad[0][2].field)
    _quarantine(db, run_id, cfg, ep, bad, totals)
    db.upsert(ep.mapping.target, cfg.source, good, now_iso())  # commit per page
    totals["ok"] += len(good)


def _run_endpoint(cfg: ConnectorConfig, ep: Endpoint, base: str, client: ApiClient, db: Database,
                  run_id: int, totals: dict[str, int]) -> str | None:
    try:
        path = ep.path.format(**{k: str(v) for k, v in ep.vars.items()})
    except KeyError as exc:
        raise FetchError(FailureCategory.CLIENT_ERROR, f"path placeholder {exc} has no value", path=ep.path) from None
    url = base.rstrip("/") + path

    plans: list[dict[str, Any]] = [{}]
    if ep.incremental:
        plans = plan_requests(ep.incremental, db.get_cursor(cfg.connector, ep.name))

    state = _EndpointState()
    try:
        for plan in plans:
            params = {**ep.params, **plan}
            for records in iter_pages(lambda u, p: client.request(ep.method, u, p), url, params,
                                      ep.pagination, ep.records_path):
                totals["pages"] += 1
                _process_page(cfg, ep, records, state, db, run_id, totals)
    except FetchError as exc:
        exc.path = exc.path or ep.path
        raise
    return state.cursor


def run_connector(
    cfg: ConnectorConfig,
    db: Database,
    vault: SecretVault,
    notifier: Notifier,
    throttle: bool = True,
    sleep: Callable[[float], None] = time.sleep,
    transport: httpx.BaseTransport | None = None,
) -> RunResult:
    began = time.monotonic()
    db.ensure_connection(cfg.connector)

    if probe_due(cfg, db):  # a probe never writes records
        probe_connector(cfg, db, vault, notifier, sleep, transport)
    before = db.get_connection(cfg.connector) or {}
    if before.get("paused"):
        return RunResult(cfg.connector, "paused", 0, 0, 0, 0, None, time.monotonic() - began,
                         message=before.get("message") or "Paused. Update the secret or run `secintegrate resume`.")

    started = now_iso()
    run_id = db.start_run(cfg.connector, started)
    totals = {"ok": 0, "bad": 0, "pages": 0}
    ctx = MessageContext(env_name=cfg.auth.secret or "", host=urlparse(cfg.base_url).hostname or "")
    category: FailureCategory | None = None
    detail: str | None = None
    client: ApiClient | None = None
    pending: dict[str, str] = {}

    try:
        for name in secret_env_names(cfg.auth):
            vault.load(name)  # fails fast, and registers the value for log redaction
        client = ApiClient(cfg, vault, throttle=throttle, sleep=sleep, transport=transport)
        for ep in cfg.endpoints:
            cursor = _run_endpoint(cfg, ep, cfg.base_url, client, db, run_id, totals)
            if cursor:
                pending[ep.name] = cursor
        for name, cursor in pending.items():  # only after every endpoint succeeded
            db.set_cursor(cfg.connector, name, cursor)
    except SecretNotFoundError as exc:
        category, detail, ctx.env_name = FailureCategory.AUTH_FAILED, f"credential {exc.name} is not stored", exc.name
    except FetchError as exc:
        category, detail = exc.category, exc.detail
        ctx.field, ctx.status, ctx.path = exc.field or "", exc.status, exc.path or ""
    except SecIntegrateError as exc:  # key store problems: the message is written to be safe to show
        category, detail = classify_exception(exc), str(exc)
        logger.error("%s: %s", cfg.connector, exc)
    except Exception as exc:
        category, detail = FailureCategory.UNKNOWN, type(exc).__name__
        logger.error("%s: unexpected %s", cfg.connector, type(exc).__name__)  # type only, no message body
    finally:
        requests = client.requests_made if client else 0
        if client:
            client.close()

    status = "failed" if category else ("partial" if totals["bad"] else "success")
    error = f"{category.value}: {detail}" if category else None
    db.finish_run(run_id, status, totals["ok"], totals["bad"], error)

    failures = (before.get("consecutive_failures") or 0) + 1 if status == "failed" else 0
    message: str | None = None
    retry_in = retry_delay_minutes(category, failures)  # transient failures retry on their own
    if category:
        message = human_message(category, ctx)
        if retry_in:
            message = f"{message or ''} Hermes will retry automatically in {retry_in} minutes.".strip()
    elif status == "partial":
        ctx.n, ctx.total = totals["bad"], totals["ok"] + totals["bad"]
        message = human_message(FailureCategory.BAD_DATA, ctx)
    elif cfg.probe is not None:  # a good run must not hide a failing probe
        last_probe = db.latest_probe(cfg.connector)
        if last_probe and not last_probe["ok"] and last_probe["category"]:
            ctx.path = cfg.probe.path
            message = human_message(FailureCategory(last_probe["category"]), ctx)
    resolved = reprocess_quarantine(cfg, db) if status in ("success", "partial") else 0
    refresh_connection(
        db, notifier, cfg.connector,
        last_run_started_at=started, last_run_finished_at=now_iso(),
        last_records_pulled=totals["ok"] + totals["bad"], last_error=error,
        last_category=category.value if category else None, consecutive_failures=failures,
        paused=int(should_pause(category, failures)), message=message,
    )
    result = RunResult(cfg.connector, status, totals["ok"], totals["bad"], totals["pages"], requests, error,
                       time.monotonic() - began, category, message, retry_in, resolved)
    logger.info(result.summary)
    return result
