"""Cron scheduling per connector (FR-4)."""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .runner import run_connector
from .storage.db import Database

logger = logging.getLogger(__name__)


def _job(cfg, db: Database) -> None:
    try:
        run_connector(cfg, db)
    except Exception:
        logger.exception("%s: scheduled run crashed", cfg.connector)


def build_scheduler(configs, db: Database) -> BackgroundScheduler:
    sched = BackgroundScheduler(timezone="UTC")
    for cfg in configs:
        if not cfg.enabled:
            continue
        sched.add_job(
            _job, CronTrigger.from_crontab(cfg.schedule, timezone="UTC"), args=[cfg, db],
            id=cfg.connector, max_instances=1, coalesce=True, misfire_grace_time=300,
        )
    return sched
