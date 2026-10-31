"""Cron scheduling per connector (FR-4), probe intervals, and the automatic recovery jobs.

One scheduler serves every account. Each account's jobs carry its email in their id, so two accounts can use the same
connector name without ever touching each other's jobs. The pre-existing workspace uses an empty owner.
"""
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
FIRST_RUN_DELAY_SECONDS = 5
FIRST_RUN_SPACING_SECONDS = 4
ADDED_RUN_DELAY_SECONDS = 1  # a connector someone just added is fetched almost at once


def _jid(owner: str, name: str) -> str:
    return f"{owner}|{name}" if owner else name


def _retry_id(connector: str, owner: str = "") -> str:
    return _jid(owner, f"{connector}__retry")


class HermesScheduler(BackgroundScheduler):  # type: ignore[misc]
    """A background scheduler that remembers what it runs, so the web UI can add and remove connectors live."""

    def __init__(self) -> None:
        super().__init__(timezone="UTC")
        self.entries: dict[tuple[str, str], tuple[ConnectorConfig, App]] = {}

    def add_connector(self, cfg: ConnectorConfig, app: App, owner: str = "") -> None:
        self.entries[(owner, cfg.connector)] = (cfg, app)
        add_connector_jobs(self, cfg, app, owner)

    def add_and_fetch(self, cfg: ConnectorConfig, app: App, owner: str = "") -> bool:
        """Start running a newly added connector and fetch its first data about a second from now.

        Returns False when nothing was scheduled (a disabled connector, or one that has already run).
        """
        self.add_connector(cfg, app, owner)
        return bool(schedule_first_runs(self, [cfg], app, owner, delay=ADDED_RUN_DELAY_SECONDS))

    def remove_connector(self, connector: str, owner: str = "") -> None:
        self.entries.pop((owner, connector), None)
        remove_connector_jobs(self, connector, owner)

    def install_recheck(self) -> None:
        self.add_job(_recheck_job, IntervalTrigger(minutes=AUTH_RECHECK_MINUTES), args=[self], id=RECHECK_JOB,
                     max_instances=1, coalesce=True, replace_existing=True)


def _run_job(cfg: ConnectorConfig, app: App, sched: BackgroundScheduler, owner: str = "") -> None:
    try:
        result = run_connector(cfg, app.db, app.vault, app.notifier)
    except Exception as exc:
        logger.error("%s: scheduled run crashed with %s", cfg.connector, type(exc).__name__)
        return
    job_id = _retry_id(cfg.connector, owner)
    if result.retry_in_minutes:  # a transient failure: try again soon instead of waiting for cron
        when = datetime.now(UTC) + timedelta(minutes=result.retry_in_minutes)
        sched.add_job(_run_job, DateTrigger(run_date=when), args=[cfg, app, sched, owner], id=job_id,
                      replace_existing=True, misfire_grace_time=300)
        logger.info("%s: automatic retry scheduled in %d minutes", cfg.connector, result.retry_in_minutes)
    elif sched.get_job(job_id):
        sched.remove_job(job_id)


def _probe_job(cfg: ConnectorConfig, app: App) -> None:
    try:
        probe_connector(cfg, app.db, app.vault, app.notifier)
    except Exception as exc:
        logger.error("%s: scheduled probe crashed with %s", cfg.connector, type(exc).__name__)


def _recheck_job(sched: HermesScheduler) -> None:
    for cfg, app in list(sched.entries.values()):
        try:
            recheck_paused(cfg, app.db, app.vault, app.notifier)
        except Exception as exc:
            logger.error("%s: credential recheck crashed with %s", cfg.connector, type(exc).__name__)


def add_connector_jobs(sched: BackgroundScheduler, cfg: ConnectorConfig, app: App, owner: str = "") -> None:
    if not cfg.enabled:
        return
    sched.add_job(
        _run_job, CronTrigger.from_crontab(cfg.schedule, timezone="UTC"), args=[cfg, app, sched, owner],
        id=_jid(owner, cfg.connector), max_instances=1, coalesce=True, misfire_grace_time=300,
        replace_existing=True,
    )
    if cfg.probe is not None:
        sched.add_job(
            _probe_job, IntervalTrigger(minutes=cfg.probe.interval_minutes), args=[cfg, app],
            id=_jid(owner, f"{cfg.connector}__probe"), max_instances=1, coalesce=True, misfire_grace_time=60,
            replace_existing=True,
        )


def remove_connector_jobs(sched: BackgroundScheduler, connector: str, owner: str = "") -> None:
    for name in (connector, f"{connector}__probe", f"{connector}__retry", f"{connector}__first"):
        job_id = _jid(owner, name)
        if sched.get_job(job_id):
            sched.remove_job(job_id)


def schedule_first_runs(sched: HermesScheduler, configs: Iterable[ConnectorConfig], app: App,
                        owner: str = "", delay: int = FIRST_RUN_DELAY_SECONDS) -> list[str]:
    """Run every enabled connector that has never run, once, a few seconds after start-up.

    Without this a new install shows an empty dashboard until each connector's next cron time (which can be a day
    away). Runs are staggered so they do not all hit the network at the same moment.
    """
    started: list[str] = []
    for cfg in configs:
        connection = app.db.get_connection(cfg.connector)
        if not cfg.enabled or (connection is not None and connection["status"] != "never_run"):
            continue
        wait = delay + FIRST_RUN_SPACING_SECONDS * len(started)
        sched.add_job(_run_job, DateTrigger(run_date=datetime.now(UTC) + timedelta(seconds=wait)),
                      args=[cfg, app, sched, owner], id=_jid(owner, f"{cfg.connector}__first"),
                      replace_existing=True, misfire_grace_time=300)
        started.append(cfg.connector)
    if started:
        logger.info("first run scheduled for: %s", ", ".join(started))
    return started


def build_scheduler(configs: Iterable[ConnectorConfig], app: App) -> HermesScheduler:
    """A scheduler for one workspace (the owner is empty). `hermes serve` builds a multi-account one itself."""
    sched = HermesScheduler()
    for cfg in configs:
        sched.add_connector(cfg, app)
    sched.install_recheck()
    return sched
