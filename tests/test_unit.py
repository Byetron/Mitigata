"""Unit tests: pagination, mapping, retry, incremental."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from secintegrate.classify import FailureCategory
from secintegrate.config.schema import FieldRule, Incremental, Pagination
from secintegrate.http.client import Page
from secintegrate.http.retry import FetchError, RetryPolicy, execute, parse_retry_after
from secintegrate.incremental import max_cursor, plan_requests, windows
from secintegrate.mapping import MappingError, apply_mapping, get_path
from secintegrate.pagination import extract_records, iter_pages, offset_done, parse_link_header


def _page(data: Any) -> Page:
    return Page(data=data, headers=httpx.Headers(), url="http://x")


# --- pagination -------------------------------------------------------------
def test_link_header() -> None:
    h = '<https://x/a?page=2>; rel="next", <https://x/a?page=9>; rel="last"'
    assert parse_link_header(h) == "https://x/a?page=2"
    assert parse_link_header('<https://x/a?page=1>; rel="prev"') is None
    assert parse_link_header(None) is None


def test_offset_stops() -> None:
    assert offset_done(100, 100, 50) and not offset_done(50, 100, 50) and offset_done(10, None, 0)


def test_offset_pages_until_total() -> None:
    seen: list[int] = []

    def fetch(url: str, params: dict[str, Any] | None) -> Page:
        assert params is not None
        start = int(params["startAt"])
        seen.append(start)
        return _page({"total": 5, "issues": list(range(start, min(start + 2, 5)))})

    pag = Pagination(type="offset", start_param="startAt", limit_param="maxResults", limit=2, total_path="total")
    pages = list(iter_pages(fetch, "u", {}, pag, "issues"))
    assert seen == [0, 2, 4] and sum(map(len, pages)) == 5


def test_page_number_stops_on_empty() -> None:
    data: dict[int, list[int]] = {1: [1], 2: [2], 3: []}

    def fetch(url: str, params: dict[str, Any] | None) -> Page:
        assert params is not None
        return _page(data[params["page"]])

    pag = Pagination(type="page_number", param="page")
    assert list(iter_pages(fetch, "u", {}, pag, "")) == [[1], [2]]


def test_cursor_pagination_follows_tokens() -> None:
    responses = {None: {"items": [1], "next": "t2"}, "t2": {"items": [2], "next": None}}

    def fetch(url: str, params: dict[str, Any] | None) -> Page:
        assert params is not None
        return _page(responses[params.get("after")])

    pag = Pagination(type="cursor", param="after", next_path="next")
    assert list(iter_pages(fetch, "u", {}, pag, "items")) == [[1], [2]]


def test_missing_records_path_is_schema_changed() -> None:
    with pytest.raises(FetchError) as info:
        extract_records({"other": []}, "vulnerabilities")
    assert info.value.category is FailureCategory.SCHEMA_CHANGED and info.value.field == "vulnerabilities"
    with pytest.raises(FetchError) as not_a_list:
        extract_records({"a": 1}, "")
    assert not_a_list.value.category is FailureCategory.SCHEMA_CHANGED


# --- mapping ----------------------------------------------------------------
def test_get_path_index() -> None:
    ok, v = get_path({"cve": {"d": [{"value": "x"}]}}, "cve.d[0].value")
    assert ok and v == "x"
    assert get_path({"a": 1}, "a.b[0]") == (False, None)


def _rules(**kw: dict[str, Any]) -> dict[str, FieldRule]:
    return {k: FieldRule.model_validate(v) for k, v in kw.items()}


def test_mapping_default_required_and_transform_errors() -> None:
    rules = _rules(a={"from": "a", "default": "dflt"}, b={"from": "b", "transform": "lower"})
    assert apply_mapping({"b": "X"}, rules) == {"a": "dflt", "b": "x"}
    with pytest.raises(MappingError, match="required field missing: id") as info:
        apply_mapping({}, _rules(id={"from": "id", "required": True}))
    assert info.value.required_missing and info.value.field == "id"
    with pytest.raises(MappingError, match="transform"):
        apply_mapping({"b": 5}, rules)
    with pytest.raises(MappingError, match="not an object"):
        apply_mapping("str", rules)


def test_mapping_const_wins_and_null_const_is_kept() -> None:
    rules = _rules(email={"const": None}, kind={"const": "kev"})
    assert apply_mapping({"anything": 1}, rules) == {"email": None, "kind": "kev"}


# --- retry ------------------------------------------------------------------
def test_backoff_sequence_and_exhaustion() -> None:
    sleeps: list[float] = []
    with pytest.raises(FetchError) as e:
        execute(lambda: httpx.Response(503), RetryPolicy(), "c", sleeps.append)
    assert e.value.category is FailureCategory.SERVER_ERROR and sleeps == [1, 2, 4]


def test_401_never_retried() -> None:
    sleeps: list[float] = []
    calls: list[int] = []

    def send() -> httpx.Response:
        calls.append(1)
        return httpx.Response(401)

    with pytest.raises(FetchError) as e:
        execute(send, RetryPolicy(), "c", sleeps.append)
    assert e.value.category is FailureCategory.AUTH_FAILED and len(calls) == 1 and not sleeps


def test_retry_after_header() -> None:
    assert parse_retry_after("7", 30) == 7 and parse_retry_after(None, 30) == 30


def test_rate_limit_waits_are_capped() -> None:
    sleeps: list[float] = []
    resp = httpx.Response(429, headers={"Retry-After": "2"})
    with pytest.raises(FetchError) as e:
        execute(lambda: resp, RetryPolicy(), "c", sleeps.append)
    assert e.value.category is FailureCategory.RATE_LIMITED and sleeps == [2.0] * 5


# --- incremental -------------------------------------------------------------
def test_nvd_windows_300_days() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    ws = windows(start, start + timedelta(days=300), 120)
    assert [(e - s).days for s, e in ws] == [120, 120, 60]


def test_cursor_format_rendering() -> None:
    inc = Incremental(cursor_field="f", param="since", format='modified >= "{value}"', initial="2026-01-01 00:00",
                      cursor_format="%Y-%m-%d %H:%M")
    assert plan_requests(inc, "2026-03-02T10:30:00Z") == [{"since": 'modified >= "2026-03-02 10:30"'}]


def test_max_cursor_ignores_garbage() -> None:
    assert max_cursor("2026-01-01T00:00:00Z", "nonsense") == "2026-01-01T00:00:00Z"
    assert max_cursor(None, "2026-03-02T10:00:00+0000") == "2026-03-02T10:00:00Z"
