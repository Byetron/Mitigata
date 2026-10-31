"""Pagination styles (FR-3): link_header, offset, page_number, cursor.

Every style has guards, because a misbehaving API can otherwise keep a run going forever or lead it somewhere it should
not go: a page limit, loop detection, and (for link headers) a same-origin check.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urljoin

import httpx

from .classify import FailureCategory
from .config.schema import Pagination
from .http.client import Page
from .http.retry import FetchError
from .mapping import get_path

logger = logging.getLogger(__name__)

Fetch = Callable[[str, dict[str, Any] | None], Page]
_SIGNATURE_SAMPLE = 20
_DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_link_header(value: str | None, rel: str = "next") -> str | None:
    """Return the URL whose rel matches, or None."""
    if not value:
        return None
    for part in re.split(r",\s*(?=<)", value):
        m = re.match(r"\s*<([^>]*)>(.*)", part, re.S)
        if not m:
            continue
        r = re.search(r'rel\s*=\s*"?([^";]+)"?', m.group(2))
        if r and rel in r.group(1).split():
            return m.group(1)
    return None


def extract_records(data: Any, records_path: str) -> list[Any]:
    """The list of records in a reply. An empty reply (no body, 204, or JSON null) means nothing new."""
    if data is None:
        return []
    if records_path:
        found, records = get_path(data, records_path)
        if not found:
            raise FetchError(FailureCategory.SCHEMA_CHANGED, "records path not found in response",
                             field=records_path)
        if records is None:
            return []
    else:
        records = data
    if not isinstance(records, list):
        raise FetchError(FailureCategory.SCHEMA_CHANGED, "expected a list of records in the response",
                         field=records_path or "response")
    return records


def offset_done(start: int, total: Any, page_len: int) -> bool:
    """Stop condition for offset paging (spec 3.4)."""
    if page_len == 0:
        return True
    return isinstance(total, int) and not isinstance(total, bool) and start >= total


def origin(url: str) -> tuple[str, str, int]:
    """(scheme, host, port): two URLs with the same origin are the same server."""
    parsed = httpx.URL(url)
    return parsed.scheme, parsed.host, parsed.port or _DEFAULT_PORTS.get(parsed.scheme, 0)


class _Guard:
    """Stops a run whose paging never ends."""

    def __init__(self, max_pages: int) -> None:
        self.max_pages = max_pages
        self.pages = 0
        self.last_signature: str | None = None
        self.seen: set[str] = set()

    @staticmethod
    def stop(reason: str) -> FetchError:
        logger.error("pagination did not end: %s", reason)  # a fixed reason only, never response content
        return FetchError(FailureCategory.UNKNOWN, f"pagination did not end: {reason}")

    def page(self, records: list[Any]) -> None:
        self.pages += 1
        if self.pages > self.max_pages:
            raise self.stop(f"more than {self.max_pages} pages")
        if records:
            sample = json.dumps(records[:_SIGNATURE_SAMPLE], sort_keys=True, default=str)
            signature = hashlib.sha256(f"{len(records)}|{sample}".encode()).hexdigest()
            if signature == self.last_signature:
                raise self.stop("the server returned the same page twice in a row")
            self.last_signature = signature

    def token(self, value: str) -> None:
        if value in self.seen:
            raise self.stop("the server repeated a paging token")
        self.seen.add(value)


def iter_pages(
    fetch: Fetch,
    url: str,
    params: dict[str, Any],
    pag: Pagination | None,
    records_path: str,
) -> Iterator[list[Any]]:
    """Yield one list of raw records per page until the stop condition."""
    if pag is None:
        yield extract_records(fetch(url, params).data, records_path)
        return

    guard = _Guard(pag.max_pages)
    if pag.type == "link_header":
        page = fetch(url, params)
        home = origin(url)
        guard.token(url)
        while True:
            records = extract_records(page.data, records_path)
            guard.page(records)
            yield records
            nxt = parse_link_header(page.headers.get("link"), pag.rel)
            if not nxt:
                return
            target = urljoin(page.url, nxt)  # relative links are legal
            if origin(target) != home:
                raise guard.stop("the next-page link points to a different server")  # never send the key there
            guard.token(target)
            page = fetch(target, None)

    elif pag.type == "offset":
        start = 0
        while True:
            p = dict(params)
            p[pag.start_param or ""] = start  # the model guarantees these are set for offset paging
            if pag.limit is not None:
                p[pag.limit_param or ""] = pag.limit
            page = fetch(url, p)
            records = extract_records(page.data, records_path)
            guard.page(records)
            yield records
            start += len(records)
            total = get_path(page.data, pag.total_path)[1] if pag.total_path else None
            if offset_done(start, total, len(records)):
                return

    elif pag.type == "page_number":
        number = pag.start
        while True:
            p = dict(params)
            p[pag.param or ""] = number
            records = extract_records(fetch(url, p).data, records_path)
            if not records:
                return
            guard.page(records)
            yield records
            number += 1

    elif pag.type == "cursor":
        p = dict(params)
        while True:
            page = fetch(url, p)
            records = extract_records(page.data, records_path)
            guard.page(records)
            yield records
            token = get_path(page.data, pag.next_path or "")[1]
            if not token:
                return
            guard.token(str(token))
            p = dict(params)
            p[pag.param or ""] = token
