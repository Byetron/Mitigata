"""Cron scheduling per connector (FR-4), probe intervals, and the automatic recovery jobs."""
from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .autoheal import AUTH_RECHECK_MINUTES
from .bootstrap import App
from .config.schema import ConnectorConfig
from .probe import probe_connector, recheck_paused
from .runner import run_connector

logger = logging.getLogger(__name__)

RECHECK_JOB = "auth_recheck"


class HermesScheduler(BackgroundScheduler):  # type: ignore[misc]
    """A background scheduler that remembers which connector configs it runs, so the web UI can add and remove them."""

    def __init__(self) -> None:
        super().__init__(timezone="UTC")
        self.known_configs: dict[str, ConnectorConfig] = {}

    def add_connector(self, cfg: ConnectorConfig, app: App) -> None:
        self.known_configs[cfg.connector] = cfg
        add_connector_jobs(self, cfg, app)

    def remove_connector(self, connector: str) -> None:
        self.known_configs.pop(connector, None)
        remove_connector_jobs(self, connector)


def _retry_id(connector: str) -> str:
    return f"{connector}__retry"


def _run_job(cfg: ConnectorConfig, app: App, sched: BackgroundScheduler) -> None:
    try:
        result = run_connector(cfg, app.db, app.vault, app.notifier)
    except Exception as exc:
        logger.error("%s: scheduled run crashed with %s", cfg.connector, type(exc).__name__)
        return
    job_id = _retry_id(cfg.connector)
    if result.retry_in_minutes:  # a transient failure: try again soon instead of waiting for cron
        when = datetime.now(UTC) + timedelta(minutes=result.retry_in_minutes)
        sched.add_job(_run_job, DateTrigger(run_date=when), args=[cfg, app, sched], id=job_id,
                      replace_existing=True, misfire_grace_time=300)
        logger.info("%s: automatic retry scheduled in %d minutes", cfg.connector, result.retry_in_minutes)
    elif sched.get_job(job_id):
        sched.remove_job(job_id)


def _probe_job(cfg: ConnectorConfig, app: App) -> None:
    try:
        probe_connector(cfg, app.db, app.vault, app.notifier)
    except Exception as exc:
        logger.error("%s: scheduled probe crashed with %s", cfg.connector, type(exc).__name__)


def _recheck_job(app: App, configs: dict[str, ConnectorConfig]) -> None:
    for cfg in list(configs.values()):
        try:
            recheck_paused(cfg, app.db, app.vault, app.notifier)
        except Exception as exc:
            logger.error("%s: credential recheck crashed with %s", cfg.connector, type(exc).__name__)


def add_connector_jobs(sched: BackgroundScheduler, cfg: ConnectorConfig, app: App) -> None:
    if not cfg.enabled:
        return
    sched.add_job(
        _run_job, CronTrigger.from_crontab(cfg.schedule, timezone="UTC"), args=[cfg, app, sched],
        id=cfg.connector, max_instances=1, coalesce=True, misfire_grace_time=300, replace_existing=True,
    )
    if cfg.probe is not None:
        sched.add_job(
            _probe_job, IntervalTrigger(minutes=cfg.probe.interval_minutes), args=[cfg, app],
            id=f"{cfg.connector}__probe", max_instances=1, coalesce=True, misfire_grace_time=60,
            replace_existing=True,
        )


def remove_connector_jobs(sched: BackgroundScheduler, connector: str) -> None:
    for job_id in (connector, f"{connector}__probe", _retry_id(connector)):
        if sched.get_job(job_id):
            sched.remove_job(job_id)


def build_scheduler(configs: Iterable[ConnectorConfig], app: App) -> HermesScheduler:
    sched = HermesScheduler()
    for cfg in configs:
        sched.add_connector(cfg, app)
    sched.add_job(_recheck_job, IntervalTrigger(minutes=AUTH_RECHECK_MINUTES), args=[app, sched.known_configs],
                  id=RECHECK_JOB, max_instances=1, coalesce=True, replace_existing=True)
    return sched
