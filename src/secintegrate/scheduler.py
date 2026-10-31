"""Cron scheduling per connector (FR-4) and interval scheduling for probes."""
from __future__ import annotations

import logging
from collections.abc import Iterable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .bootstrap import App
from .config.schema import ConnectorConfig
from .probe import probe_connector
from .runner import run_connector

logger = logging.getLogger(__name__)


def _run_job(cfg: ConnectorConfig, app: App) -> None:
    try:
        run_connector(cfg, app.db, app.vault, app.notifier)
    except Exception as exc:
        logger.error("%s: scheduled run crashed with %s", cfg.connector, type(exc).__name__)


def _probe_job(cfg: ConnectorConfig, app: App) -> None:
    try:
        probe_connector(cfg, app.db, app.vault, app.notifier)
    except Exception as exc:
        logger.error("%s: scheduled probe crashed with %s", cfg.connector, type(exc).__name__)


def build_scheduler(configs: Iterable[ConnectorConfig], app: App) -> BackgroundScheduler:
    sched = BackgroundScheduler(timezone="UTC")
    for cfg in configs:
        if not cfg.enabled:
            continue
        sched.add_job(
            _run_job, CronTrigger.from_crontab(cfg.schedule, timezone="UTC"), args=[cfg, app],
            id=cfg.connector, max_instances=1, coalesce=True, misfire_grace_time=300,
        )
        if cfg.probe is not None:
            sched.add_job(
                _probe_job, IntervalTrigger(minutes=cfg.probe.interval_minutes), args=[cfg, app],
                id=f"{cfg.connector}__probe", max_instances=1, coalesce=True, misfire_grace_time=60,
            )
    return sched
