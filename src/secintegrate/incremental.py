"""Incremental sync (B1): cursor rendering, request planning, NVD date windows."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .transforms import parse_dt, to_iso


def _render(dt: datetime, inc) -> str:
    return dt.strftime(inc.cursor_format) if inc.cursor_format else to_iso(dt)


def start_datetime(inc, stored: str | None) -> datetime:
    raw = stored or inc.initial
    return parse_dt(raw) - timedelta(minutes=inc.lookback_minutes)


def windows(start: datetime, end: datetime, days: int) -> list[tuple[datetime, datetime]]:
    """Split [start, end] into chunks of at most `days` days."""
    out = []
    step = timedelta(days=days)
    while start < end:
        stop = min(start + step, end)
        out.append((start, stop))
        start = stop
    return out


def plan_requests(inc, stored: str | None, now: datetime | None = None) -> list[dict[str, Any]]:
    """Return one params dict per request series (several for NVD windows)."""
    now = now or datetime.now(timezone.utc)
    start = start_datetime(inc, stored)
    if inc.param:
        value = _render(start, inc)
        return [{inc.param: inc.format.replace("{value}", value)}]
    return [
        {inc.start_param: _render(s, inc), inc.end_param: _render(e, inc)}
        for s, e in windows(start, now, inc.window_days)
    ]


def max_cursor(current: str | None, candidate: Any) -> str | None:
    """Keep the larger of two timestamps, normalised to UTC ISO. Bad values are ignored."""
    try:
        dt = parse_dt(str(candidate))
    except (TypeError, ValueError):
        return current
    if current is None or dt > parse_dt(current):
        return to_iso(dt)
    return current
