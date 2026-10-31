"""Retry and backoff policy (FR-7, spec 5.3). Hand-written so the policy is visible."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from ..classify import FailureCategory, classify_status

logger = logging.getLogger(__name__)

MAX_WAIT = 3600.0


class FetchError(Exception):
    """A request failed for good. `category` is the shared failure vocabulary (brief 2.3)."""

    def __init__(self, category: FailureCategory, detail: str, status: int | None = None,
                 field: str | None = None, path: str | None = None) -> None:
        super().__init__(f"{category.value}: {detail}")
        self.category = category
        self.detail = detail
        self.status = status
        self.field = field
        self.path = path

    @property
    def code(self) -> str:
        return self.category.value


@dataclass
class RetryPolicy:
    max_retries: int = 3
    backoff_seconds: list[float] = field(default_factory=lambda: [1.0, 2.0, 4.0])
    retry_after_default: float = 30.0
    max_rate_limit_waits: int = 5

    @classmethod
    def from_config(cls, cfg: Any) -> RetryPolicy:
        if cfg is None:
            return cls()
        return cls(
            max_retries=cfg.max_retries,
            backoff_seconds=list(cfg.backoff_seconds),
            retry_after_default=cfg.retry_after_default,
        )

    def backoff(self, attempt: int) -> float:
        return float(self.backoff_seconds[min(attempt, len(self.backoff_seconds) - 1)])


def parse_retry_after(value: str | None, default: float) -> float:
    if not value:
        return default
    value = value.strip()
    try:
        return min(max(float(value), 0.0), MAX_WAIT)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        return min(max((when - datetime.now(UTC)).total_seconds(), 0.0), MAX_WAIT)
    except (TypeError, ValueError):
        return default


def _is_rate_limited(resp: httpx.Response) -> bool:
    if resp.status_code == 429:  # noqa: PLR2004
        return True
    # GitHub signals an exhausted limit with 403 plus these headers.
    return resp.status_code == 403 and (  # noqa: PLR2004
        "retry-after" in resp.headers or resp.headers.get("x-ratelimit-remaining") == "0"
    )


def execute(
    send: Callable[[], httpx.Response],
    policy: RetryPolicy,
    label: str,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """Call send() until it yields a usable response or the policy gives up."""
    retries = 0
    rate_waits = 0
    while True:
        try:
            resp = send()
        except httpx.TransportError as exc:
            if retries >= policy.max_retries:
                raise FetchError(
                    FailureCategory.NETWORK, f"{type(exc).__name__} for {label} after {retries} retries"
                ) from None
            wait = policy.backoff(retries)
            retries += 1
            logger.warning("%s: %s, retry %d in %.1fs", label, type(exc).__name__, retries, wait)
            sleep(wait)
            continue

        status = resp.status_code
        category = classify_status(status)
        if _is_rate_limited(resp):
            if rate_waits >= policy.max_rate_limit_waits:
                raise FetchError(FailureCategory.RATE_LIMITED,
                                 f"HTTP {status} for {label}, gave up after {rate_waits} waits", status)
            wait = parse_retry_after(resp.headers.get("retry-after"), policy.retry_after_default)
            rate_waits += 1
            logger.warning("%s: rate limited (HTTP %d), waiting %.1fs", label, status, wait)
            sleep(wait)
            continue
        if category is None:
            return resp
        if category is FailureCategory.SERVER_ERROR:
            if retries >= policy.max_retries:
                raise FetchError(category, f"HTTP {status} for {label} after {retries} retries", status)
            wait = policy.backoff(retries)
            retries += 1
            logger.warning("%s: HTTP %d, retry %d in %.1fs", label, status, retries, wait)
            sleep(wait)
            continue
        raise FetchError(category, f"HTTP {status} for {label}", status)  # auth, not found, other 4xx: no retry
