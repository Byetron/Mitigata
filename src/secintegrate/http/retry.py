"""Retry and backoff policy (FR-7, spec 5.3). Hand-written so the policy is visible."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable

import httpx

logger = logging.getLogger(__name__)

RETRY_STATUSES = {500, 502, 503, 504}
MAX_WAIT = 3600.0


class FetchError(Exception):
    """A request failed for good. `code` is the shared failure vocabulary (A3)."""

    def __init__(self, code: str, detail: str, status: int | None = None):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.status = status


@dataclass
class RetryPolicy:
    max_retries: int = 3
    backoff_seconds: list[float] = field(default_factory=lambda: [1.0, 2.0, 4.0])
    retry_after_default: float = 30.0
    max_rate_limit_waits: int = 5

    @classmethod
    def from_config(cls, cfg) -> "RetryPolicy":
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
            when = when.replace(tzinfo=timezone.utc)
        return min(max((when - datetime.now(timezone.utc)).total_seconds(), 0.0), MAX_WAIT)
    except (TypeError, ValueError):
        return default


def _is_rate_limited(resp: httpx.Response) -> bool:
    if resp.status_code == 429:
        return True
    # GitHub signals an exhausted limit with 403 plus these headers.
    return resp.status_code == 403 and (
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
                    "network_error", f"{type(exc).__name__} for {label} after {retries} retries"
                ) from None
            wait = policy.backoff(retries)
            retries += 1
            logger.warning("%s: %s, retry %d in %.1fs", label, type(exc).__name__, retries, wait)
            sleep(wait)
            continue

        status = resp.status_code
        if _is_rate_limited(resp):
            if rate_waits >= policy.max_rate_limit_waits:
                raise FetchError("rate_limited", f"HTTP {status} for {label}, gave up after {rate_waits} waits", status)
            wait = parse_retry_after(resp.headers.get("retry-after"), policy.retry_after_default)
            rate_waits += 1
            logger.warning("%s: rate limited (HTTP %d), waiting %.1fs", label, status, wait)
            sleep(wait)
            continue
        if status >= 500:
            if retries >= policy.max_retries:
                raise FetchError("server_error", f"HTTP {status} for {label} after {retries} retries", status)
            wait = policy.backoff(retries)
            retries += 1
            logger.warning("%s: HTTP %d, retry %d in %.1fs", label, status, retries, wait)
            sleep(wait)
            continue
        if status in (401, 403):
            raise FetchError("auth_failed", f"HTTP {status} for {label}", status)
        if status == 404:
            raise FetchError("not_found", f"HTTP 404 for {label}", status)
        if status >= 400:
            raise FetchError("client_error", f"HTTP {status} for {label}", status)
        return resp
