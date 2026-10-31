"""Runs scripts/simulate_api_errors.py as a regression test, plus direct tests of each hardening fix."""
from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from secintegrate.http.retry import FetchError, RetryPolicy, execute
from secintegrate.incremental import max_cursor
from secintegrate.pagination import extract_records, origin

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "simulate_api_errors.py"


def load_simulator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("simulate_api_errors", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["simulate_api_errors"] = module  # dataclasses in the script need to find their own module
    spec.loader.exec_module(module)
    return module


SIMULATOR = load_simulator()
SCENARIOS = SIMULATOR.SCENARIOS


@pytest.mark.parametrize("item", SCENARIOS, ids=[f"{s.group[:1]}-{s.name}" for s in SCENARIOS])
def test_scenario_behaves_as_designed(item: object) -> None:
    _, problem = item.run()  # type: ignore[attr-defined]
    assert problem is None, problem


def test_there_are_many_scenarios() -> None:
    assert len(SCENARIOS) >= 30


# --- direct tests of each fix ------------------------------------------------------------------------
def test_retry_after_longer_than_the_cap_is_not_slept_through() -> None:
    sleeps: list[float] = []
    resp = httpx.Response(429, headers={"Retry-After": "3600"})
    with pytest.raises(FetchError) as info:
        execute(lambda: resp, RetryPolicy(), "c", sleeps.append)
    assert not sleeps and "asked to wait 3600s" in info.value.detail


def test_503_retry_after_is_honoured() -> None:
    sleeps: list[float] = []
    answers = iter([httpx.Response(503, headers={"Retry-After": "120"}), httpx.Response(200)])
    execute(lambda: next(answers), RetryPolicy(), "c", sleeps.append)
    assert sleeps == [120.0]


def test_cursor_ignores_far_future_dates() -> None:
    now = datetime(2026, 10, 31, tzinfo=UTC)
    assert max_cursor("2026-10-01T00:00:00Z", "9999-12-31T00:00:00Z", now) == "2026-10-01T00:00:00Z"
    assert max_cursor(None, "2026-10-31T12:00:00Z", now) == "2026-10-31T12:00:00Z"  # a few hours ahead is fine


def test_empty_replies_mean_no_records() -> None:
    assert extract_records(None, "") == [] and extract_records(None, "data") == []
    assert extract_records({"data": None}, "data") == []


def test_origin_compares_scheme_host_and_port() -> None:
    assert origin("https://a.test/x") == origin("https://a.test:443/y")
    assert origin("https://a.test/x") != origin("http://a.test/x")
    assert origin("https://a.test/x") != origin("https://b.test/x")
    assert origin("https://a.test/x") != origin("https://a.test:8443/x")
