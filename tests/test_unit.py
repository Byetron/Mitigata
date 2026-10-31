from datetime import datetime, timedelta, timezone

import httpx
import pytest

from conftest import make_cfg
from secintegrate.config.validator import validate_text
from secintegrate.http.retry import FetchError, RetryPolicy, execute, parse_retry_after
from secintegrate.incremental import max_cursor, plan_requests, windows
from secintegrate.mapping import MappingError, apply_mapping, get_path
from secintegrate.pagination import iter_pages, offset_done, parse_link_header
from secintegrate.config.schema import FieldRule, Pagination


# --- pagination -------------------------------------------------------------
def test_link_header():
    h = '<https://x/a?page=2>; rel="next", <https://x/a?page=9>; rel="last"'
    assert parse_link_header(h) == "https://x/a?page=2"
    assert parse_link_header('<https://x/a?page=1>; rel="prev"') is None
    assert parse_link_header(None) is None


def test_offset_stops():
    assert offset_done(100, 100, 50) and not offset_done(50, 100, 50) and offset_done(10, None, 0)


class _P:
    def __init__(self, data, headers=None):
        self.data, self.headers = data, httpx.Headers(headers or {})


def test_offset_pages_until_total():
    seen = []

    def fetch(url, params):
        seen.append(params["startAt"])
        return _P({"total": 5, "issues": list(range(params["startAt"], min(params["startAt"] + 2, 5)))})

    pag = Pagination(type="offset", start_param="startAt", limit_param="maxResults", limit=2, total_path="total")
    pages = list(iter_pages(fetch, "u", {}, pag, "issues"))
    assert seen == [0, 2, 4] and sum(map(len, pages)) == 5


def test_page_number_stops_on_empty():
    data = {1: [1], 2: [2], 3: []}
    pag = Pagination(type="page_number", param="page")
    pages = list(iter_pages(lambda u, p: _P(data[p["page"]]), "u", {}, pag, ""))
    assert pages == [[1], [2]]


# --- mapping ----------------------------------------------------------------
def test_get_path_index():
    ok, v = get_path({"cve": {"d": [{"value": "x"}]}}, "cve.d[0].value")
    assert ok and v == "x"
    assert get_path({"a": 1}, "a.b[0]") == (False, None)


def _rules(**kw):
    return {k: FieldRule.model_validate(v) for k, v in kw.items()}


def test_mapping_default_required_and_transform_errors():
    rules = _rules(a={"from": "a", "default": "dflt"}, b={"from": "b", "transform": "lower"})
    assert apply_mapping({"b": "X"}, rules) == {"a": "dflt", "b": "x"}
    with pytest.raises(MappingError, match="required field missing: id"):
        apply_mapping({}, _rules(id={"from": "id", "required": True, "default": "z"}))
    with pytest.raises(MappingError, match="transform"):
        apply_mapping({"b": 5}, rules)
    with pytest.raises(MappingError, match="not an object"):
        apply_mapping("str", rules)


# --- retry ------------------------------------------------------------------
def test_backoff_sequence_and_exhaustion():
    sleeps = []

    def send():
        return httpx.Response(503)

    with pytest.raises(FetchError) as e:
        execute(send, RetryPolicy(), "c", sleeps.append)
    assert e.value.code == "server_error" and sleeps == [1, 2, 4]


def test_401_never_retried():
    sleeps, calls = [], []
    with pytest.raises(FetchError) as e:
        execute(lambda: (calls.append(1), httpx.Response(401))[1], RetryPolicy(), "c", sleeps.append)
    assert e.value.code == "auth_failed" and len(calls) == 1 and not sleeps


def test_retry_after_header():
    assert parse_retry_after("7", 30) == 7 and parse_retry_after(None, 30) == 30


# --- incremental -------------------------------------------------------------
def test_nvd_windows_300_days():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ws = windows(start, start + timedelta(days=300), 120)
    assert [(e - s).days for s, e in ws] == [120, 120, 60]


def test_cursor_format_rendering():
    from secintegrate.config.schema import Incremental
    inc = Incremental(cursor_field="f", param="since", format='modified >= "{value}"', initial="2026-01-01 00:00",
                      cursor_format="%Y-%m-%d %H:%M")
    assert plan_requests(inc, "2026-03-02T10:30:00Z") == [{"since": 'modified >= "2026-03-02 10:30"'}]


def test_max_cursor_ignores_garbage():
    assert max_cursor("2026-01-01T00:00:00Z", "nonsense") == "2026-01-01T00:00:00Z"
    assert max_cursor(None, "2026-03-02T10:00:00+0000") == "2026-03-02T10:00:00Z"


# --- validator (B2) -----------------------------------------------------------
GOOD = """
connector: demo
source: demo
schedule: "*/5 * * * *"
base_url: https://example.com
auth: {type: bearer, secret: DEMO_TOKEN}
endpoints:
  - name: e
    path: /x
    mapping:
      target: event
      fields:
        id: {from: id, required: true}
        type: {const: t}
"""


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DEMO_TOKEN", "abcd1234")


def _errs(text, **kw):
    return {(i.path, i.message) for i in validate_text(text, "t.yaml", **kw)[1]}


def test_good_config_passes():
    assert validate_text(GOOD, "t.yaml")[1] == []


@pytest.mark.parametrize("old,new,path,fragment", [
    ("secret: DEMO_TOKEN", "secret: ghp_realLookingKey123", "auth.secret", "looks like a real value"),
    ('"*/5 * * * *"', '"*/5 * *"', "schedule", "has 3 fields, expected 5"),
    ("target: event", "target: gadget", "endpoints[0].mapping.target", "must be one of user, device, event"),
    ("{from: id, required: true}", "{from: id, transform: lowr}", "endpoints[0].mapping.fields.id.transform", "Did you mean lower"),
    ("path: /x", "path: /x\n    pagination: {type: offset}", "endpoints[0].pagination", "requires start_param and limit_param"),
    ("secret: DEMO_TOKEN", "secret: MISSING_VAR_XYZ", "auth.secret", "MISSING_VAR_XYZ is not set"),
])
def test_validator_rules(old, new, path, fragment):
    text = GOOD.replace(old, new)
    assert any(p == path and fragment in m for p, m in _errs(text)), _errs(text)


def test_type_error_message_and_duplicate():
    text = GOOD.replace("path: /x", "path: /x\n    pagination: {type: offset, start_param: a, limit_param: b, limit: fifty}")
    assert ("endpoints[0].pagination.limit", 'expected integer, got "fifty"') in _errs(text)
    assert any("defined in two files" in m for _, m in _errs(GOOD, known_ids={"demo"}))
