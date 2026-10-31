"""httpx wrapper: static headers, auth, throttle, retry (FR-1, FR-7, FR-8)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from ..auth import build_auth_headers, secret_env_names
from ..secrets import MissingSecret
from .ratelimit import TokenBucket
from .retry import FetchError, RetryPolicy, execute

logger = logging.getLogger(__name__)


@dataclass
class Page:
    data: Any
    headers: httpx.Headers
    url: str


class ApiClient:
    def __init__(
        self,
        cfg,
        throttle: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        transport: httpx.BaseTransport | None = None,
    ):
        self.cfg = cfg
        self.sleep = sleep
        self.http = httpx.Client(timeout=30.0, transport=transport, follow_redirects=True)
        rl = cfg.rate_limit
        self.bucket = TokenBucket(rl.max_requests, rl.per_seconds, sleep=sleep) if rl and throttle else None
        self.policy = RetryPolicy.from_config(cfg.retry)
        self.requests_made = 0

    def close(self) -> None:
        self.http.close()

    def request(self, method: str, url: str, params: dict[str, Any] | None = None) -> Page:
        try:
            headers = {**self.cfg.headers, **build_auth_headers(self.cfg.auth)}
        except MissingSecret as exc:
            raise FetchError("config_error", f"env {exc} is not set") from None
        full_url = str(httpx.URL(url).copy_merge_params(params or {}))

        def send() -> httpx.Response:
            if self.bucket:
                self.bucket.acquire()
            self.requests_made += 1
            logger.info("%s %s %s", self.cfg.connector, method, full_url)
            if method == "POST":
                return self.http.request("POST", url, json=params or None, headers=headers)
            return self.http.request("GET", url, params=params or None, headers=headers)

        try:
            resp = execute(send, self.policy, self.cfg.connector, self.sleep)
        except FetchError as exc:
            if exc.code == "auth_failed":
                envs = ", ".join(secret_env_names(self.cfg.auth))
                exc.detail = f"{exc.detail} (env {envs})"
                exc.args = (f"{exc.code}: {exc.detail}",)
            raise
        try:
            data = resp.json()
        except ValueError:
            raise FetchError("bad_response", f"malformed JSON from {self.cfg.connector}") from None
        return Page(data=data, headers=resp.headers, url=str(resp.url))
