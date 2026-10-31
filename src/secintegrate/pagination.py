"""Pagination styles (FR-3): link_header, offset, page_number, cursor."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from .classify import FailureCategory
from .config.schema import Pagination
from .http.client import Page
from .http.retry import FetchError
from .mapping import get_path

Fetch = Callable[[str, dict[str, Any] | None], Page]


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
    if records_path:
        found, records = get_path(data, records_path)
        if not found:
            raise FetchError(FailureCategory.SCHEMA_CHANGED, "records path not found in response",
                             field=records_path)
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

    if pag.type == "link_header":
        page = fetch(url, params)
        while True:
            yield extract_records(page.data, records_path)
            nxt = parse_link_header(page.headers.get("link"), pag.rel)
            if not nxt:
                return
            page = fetch(nxt, None)

    elif pag.type == "offset":
        start = 0
        while True:
            p = dict(params)
            p[pag.start_param or ""] = start  # the model guarantees these are set for offset paging
            if pag.limit is not None:
                p[pag.limit_param or ""] = pag.limit
            page = fetch(url, p)
            records = extract_records(page.data, records_path)
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
            yield records
            number += 1

    elif pag.type == "cursor":
        p = dict(params)
        while True:
            page = fetch(url, p)
            yield extract_records(page.data, records_path)
            token = get_path(page.data, pag.next_path or "")[1]
            if not token:
                return
            p = dict(params)
            p[pag.param or ""] = token
