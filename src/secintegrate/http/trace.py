"""A record of one HTTP request to an API: enough to explain what went wrong, never enough to leak a secret.

Only the method, host, path, the NAMES of query parameters, the status, timing, size and a few headers that explain
rate limiting are kept. No header values that could carry a login, no query values, and never a response body.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import httpx

from ..secrets import redact

_RATE_HEADERS = ("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining")


@dataclass(frozen=True)
class RequestRecord:
    kind: str  # run, probe or diagnose
    method: str
    host: str
    path: str
    params: str  # parameter names only, comma separated
    status: int | None
    latency_ms: int
    bytes: int | None
    content_type: str | None
    rate_remaining: str | None
    retry_after: str | None
    error: str | None  # the exception type when no reply arrived


Recorder = Callable[[RequestRecord], None]


def make_record(kind: str, method: str, url: str, params: dict[str, object] | None, latency_ms: int,
                response: httpx.Response | None = None, error: str | None = None) -> RequestRecord:
    parsed = httpx.URL(url)
    names = sorted({*dict(parsed.params).keys(), *(params or {}).keys()})
    headers = response.headers if response is not None else httpx.Headers()
    media = headers.get("content-type", "").split(";")[0].strip() or None
    remaining = next((headers[h] for h in _RATE_HEADERS if h in headers), None)
    return RequestRecord(
        kind=kind, method=method, host=parsed.host, path=redact(parsed.path), params=",".join(names),
        status=response.status_code if response is not None else None, latency_ms=latency_ms,
        bytes=len(response.content) if response is not None else None, content_type=media,
        rate_remaining=remaining, retry_after=headers.get("retry-after"), error=error,
    )
