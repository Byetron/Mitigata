"""httpx wrapper: static headers, auth, throttle, retry (FR-1, FR-7, FR-8)."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from ..auth import build_auth_headers, secret_env_names
from ..classify import FailureCategory
from ..config.schema import ConnectorConfig, Probe
from ..security.errors import SecretNotFoundError
from ..security.vault import SecretVault
from .ratelimit import TokenBucket
from .retry import FetchError, RetryPolicy, execute

logger = logging.getLogger(__name__)


@dataclass
class Page:
    data: Any
    headers: httpx.Headers
    url: str


@dataclass
class ProbeResponse:
    status: int
    latency_ms: int


class ApiClient:
    def __init__(
        self,
        cfg: ConnectorConfig,
        vault: SecretVault,
        throttle: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self.vault = vault
        self.sleep = sleep
        home = httpx.URL(cfg.base_url)
        self._home = (home.scheme, home.host, home.port or (443 if home.scheme == "https" else 80))
        self._secret_headers = {"authorization", (cfg.auth.header or "").lower()} - {""}
        self.http = httpx.Client(timeout=30.0, transport=transport, follow_redirects=True,
                                 event_hooks={"request": [self._keep_secrets_home]})
        rl = cfg.rate_limit
        self.bucket = TokenBucket(rl.max_requests, rl.per_seconds, sleep=sleep) if rl and throttle else None
        self.policy = RetryPolicy.from_config(cfg.retry)
        self.requests_made = 0

    def _keep_secrets_home(self, request: httpx.Request) -> None:
        """Runs for every request, including each redirect hop: login headers only ever go to the configured server."""
        url = request.url
        if (url.scheme, url.host, url.port or (443 if url.scheme == "https" else 80)) != self._home:
            for name in self._secret_headers:
                if name in request.headers:
                    del request.headers[name]

    def close(self) -> None:
        self.http.close()

    def _headers(self) -> dict[str, str]:
        try:
            return {**self.cfg.headers, **build_auth_headers(self.cfg.auth, self.vault)}
        except SecretNotFoundError as exc:
            raise FetchError(FailureCategory.AUTH_FAILED, f"credential {exc.name} is not stored") from exc

    def _send(self, method: str, url: str, params: dict[str, Any] | None, policy: RetryPolicy) -> httpx.Response:
        headers = self._headers()
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
            return execute(send, policy, self.cfg.connector, self.sleep)
        except FetchError as exc:
            if exc.category is FailureCategory.AUTH_FAILED:
                names = ", ".join(secret_env_names(self.cfg.auth))
                exc.detail = f"{exc.detail} (secret {names})"
                exc.args = (f"{exc.category.value}: {exc.detail}",)
            raise

    def request(self, method: str, url: str, params: dict[str, Any] | None = None) -> Page:
        resp = self._send(method, url, params, self.policy)
        data: Any = None  # no body (204, or an empty reply) means nothing new, not an error
        if resp.status_code != httpx.codes.NO_CONTENT and resp.content.strip():
            try:
                data = resp.json()
            except ValueError:
                raise FetchError(FailureCategory.UNKNOWN, f"malformed JSON from {self.cfg.connector}") from None
        return Page(data=data, headers=resp.headers, url=str(resp.url))

    def probe(self, probe: Probe, base_url: str) -> ProbeResponse:
        """One request: no pagination, no mapping, no retries. Uses the normal auth and throttle."""
        policy = RetryPolicy(max_retries=0, max_rate_limit_waits=0)
        started = time.monotonic()
        resp = self._send(probe.method, base_url.rstrip("/") + probe.path, probe.params or None, policy)
        return ProbeResponse(status=resp.status_code, latency_ms=round((time.monotonic() - started) * 1000))
