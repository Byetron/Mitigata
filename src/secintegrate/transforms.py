"""Transform registry (spec 3.7). A raising transform quarantines the record."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable


def parse_dt(value: str) -> datetime:
    """Parse an ISO-8601 string (with or without offset) to an aware UTC datetime."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scalar(v: Any) -> Any:
    if isinstance(v, (dict, list)):
        raise ValueError("expected a scalar value")
    return v


def to_string(v: Any) -> str:
    return str(_scalar(v))


def lower(v: Any) -> str:
    return _str(v).lower()


def upper(v: Any) -> str:
    return _str(v).upper()


def strip(v: Any) -> str:
    return _str(v).strip()


def _str(v: Any) -> str:
    if not isinstance(v, str):
        raise ValueError(f"expected string, got {type(v).__name__}")
    return v


def iso8601(v: Any) -> str:
    return to_iso(parse_dt(_str(v)))


def epoch_ms_to_iso(v: Any) -> str:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError("expected integer milliseconds")
    return to_iso(datetime.fromtimestamp(v / 1000, tz=timezone.utc))


def active_to_status(v: Any) -> str:
    if not isinstance(v, bool):
        raise ValueError("expected boolean")
    return "active" if v else "disabled"


TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "to_string": to_string,
    "lower": lower,
    "upper": upper,
    "strip": strip,
    "iso8601": iso8601,
    "epoch_ms_to_iso": epoch_ms_to_iso,
    "active_to_status": active_to_status,
}
