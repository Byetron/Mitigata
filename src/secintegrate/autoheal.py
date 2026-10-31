"""Automatic recovery for failures a machine can safely fix on its own.

Nothing here rewrites a config. It retries later, re-checks credentials, and re-tries stored bad records.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .classify import FailureCategory
from .config.schema import ConnectorConfig
from .mapping import MappingError, apply_mapping
from .storage.db import Database, now_iso

logger = logging.getLogger(__name__)

# Failures that usually clear by themselves: retry soon instead of waiting for the next cron time.
TRANSIENT = frozenset({FailureCategory.SERVER_ERROR, FailureCategory.NETWORK, FailureCategory.RATE_LIMITED})
RETRY_DELAYS_MINUTES = (5, 15, 45)
AUTH_RECHECK_MINUTES = 60
QUARANTINE_BATCH = 500


def retry_delay_minutes(category: FailureCategory | None, consecutive_failures: int) -> int | None:
    """Minutes until an automatic retry, or None when the next scheduled run should decide.

    Delays grow (5, 15, 45 minutes). After the third failed retry Hermes stops retrying early,
    so a long outage does not turn into a stream of requests.
    """
    if category not in TRANSIENT or not 1 <= consecutive_failures <= len(RETRY_DELAYS_MINUTES):
        return None
    return RETRY_DELAYS_MINUTES[consecutive_failures - 1]


def reprocess_quarantine(cfg: ConnectorConfig, db: Database, limit: int = QUARANTINE_BATCH) -> int:
    """Run stored bad records through the current mapping. Records that now map are saved and released.

    This is how a fixed mapping, or a source that corrected its data, clears old `bad_data` entries.
    """
    resolved = 0
    endpoints = {ep.name: ep for ep in cfg.endpoints}
    for row in db.quarantined(cfg.connector, limit):
        ep = endpoints.get(row["endpoint"])
        if ep is None:
            continue
        try:
            record: Any = json.loads(row["raw_json"])
            mapped = apply_mapping(record, ep.mapping.fields)
        except (MappingError, ValueError):
            continue
        if mapped.get("id") in (None, ""):
            continue
        db.upsert(ep.mapping.target, cfg.source, [mapped], now_iso())
        db.delete_quarantine(row["id"])
        resolved += 1
    if resolved:
        logger.info("%s: %d quarantined record(s) now map cleanly and were saved", cfg.connector, resolved)
    return resolved
