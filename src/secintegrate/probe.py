"""Canary probes (brief 2.2): one cheap request that checks a connection and never writes records."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx

from .classify import FailureCategory, classify_exception
from .config.schema import ConnectorConfig
from .health import PAUSE_AFTER, refresh_connection
from .http.client import ApiClient
from .http.retry import FetchError
from .http.trace import Recorder
from .notify import Notifier
from .remediate import MessageContext, human_message
from .security.errors import SecIntegrateError
from .security.ports import SecretLoader
from .security.vault import SecretVault
from .storage.db import Database

logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    ok: bool
    category: FailureCategory | None
    status: int | None
    latency_ms: int | None


def probe_due(cfg: ConnectorConfig, db: Database, now: datetime | None = None) -> bool:
    if cfg.probe is None:
        return False
    last = db.latest_probe(cfg.connector)
    if last is None:
        return True
    moment = now or datetime.now(UTC)
    checked = datetime.strptime(last["checked_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return moment - checked >= timedelta(minutes=cfg.probe.interval_minutes)


def probe_connector(
    cfg: ConnectorConfig,
    db: Database,
    vault: SecretVault,
    notifier: Notifier,
    sleep: Callable[[float], None] = time.sleep,
    transport: httpx.BaseTransport | None = None,
) -> ProbeResult | None:
    """Run one probe, store the result, and update the connection's health. Skips paused connectors."""
    if cfg.probe is None:
        return None
    db.ensure_connection(cfg.connector)
    current = db.get_connection(cfg.connector) or {}
    if current.get("paused"):
        return None

    result = _send_probe(cfg, vault, sleep, transport, db.recorder(cfg.connector))
    db.add_probe(cfg.connector, result.ok, result.category.value if result.category else None,
                 result.status, result.latency_ms)

    updates: dict[str, object] = {}
    run = db.latest_run(cfg.connector)
    run_failed = bool(run and run["status"] == "failed")
    if result.ok:
        if not run or run["status"] == "success":
            updates["message"] = None
    else:
        recent = db.recent_probes(cfg.connector, PAUSE_AFTER)
        if (result.category is FailureCategory.AUTH_FAILED and len(recent) == PAUSE_AFTER
                and all(p["category"] == FailureCategory.AUTH_FAILED.value for p in recent)):
            updates["paused"] = 1
        if not run_failed and result.category is not None:
            ctx = MessageContext(env_name=cfg.auth.secret or "", path=cfg.probe.path,
                                 host=urlparse(cfg.base_url).hostname or "", status=result.status)
            updates["message"] = human_message(result.category, ctx)
    refresh_connection(db, notifier, cfg.connector, **updates)
    return result


def _send_probe(cfg: ConnectorConfig, vault: SecretLoader, sleep: Callable[[float], None],
                transport: httpx.BaseTransport | None, recorder: Recorder | None = None) -> ProbeResult:
    assert cfg.probe is not None  # noqa: S101 - callers check; keeps the type checker precise
    client = ApiClient(cfg, vault, sleep=sleep, transport=transport, recorder=recorder, kind="probe")
    try:
        response = client.probe(cfg.probe, cfg.base_url)
    except (FetchError, SecIntegrateError, httpx.HTTPError) as exc:
        category = classify_exception(exc)
        status = exc.status if isinstance(exc, FetchError) else None
        if category is FailureCategory.RATE_LIMITED:  # reachable and logged in: only busy
            return ProbeResult(True, None, status, None)
        if category is FailureCategory.UNKNOWN:
            logger.error("probe for %s failed with an unexpected %s", cfg.connector, type(exc).__name__)
        return ProbeResult(False, category, status, None)
    finally:
        client.close()
    if response.status != cfg.probe.expect_status:
        logger.error("probe for %s returned status %d, expected %d", cfg.connector, response.status,
                     cfg.probe.expect_status)
        return ProbeResult(False, FailureCategory.UNKNOWN, response.status, response.latency_ms)
    return ProbeResult(True, None, response.status, response.latency_ms)


def recheck_paused(
    cfg: ConnectorConfig,
    db: Database,
    vault: SecretVault,
    notifier: Notifier,
    sleep: Callable[[float], None] = time.sleep,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    """Auto-resume: one probe for a connector paused by auth failures. If it passes, the pause is lifted.

    This covers a key that was fixed at the provider, or a provider outage that looked like a bad key.
    A connector with no probe is never rechecked, because a real sync could repeat a rejected login.
    """
    current = db.get_connection(cfg.connector) or {}
    if cfg.probe is None or not current.get("paused"):
        return False
    if current.get("last_category") not in (None, FailureCategory.AUTH_FAILED.value):
        return False
    result = _send_probe(cfg, vault, sleep, transport, db.recorder(cfg.connector))
    db.add_probe(cfg.connector, result.ok, result.category.value if result.category else None,
                 result.status, result.latency_ms)
    if not result.ok:
        return False
    logger.info("%s: credential works again, resuming automatically", cfg.connector)
    refresh_connection(db, notifier, cfg.connector, paused=0, consecutive_failures=0, message=None)
    return True
