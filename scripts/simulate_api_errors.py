"""Simulate misbehaving APIs against Hermes's real runner and report what happens.

Nothing here touches the network or your data: every request goes to an in-process fake server, with a throwaway
database and a fake key. Run it with:   python scripts/simulate_api_errors.py

Each scenario states the behaviour Hermes SHOULD have. A line marked PROBLEM is a blind spot or an inconsistency.
"""
from __future__ import annotations

import json
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import httpx

from secintegrate.config.schema import ConnectorConfig
from secintegrate.notify import StateChange
from secintegrate.probe import probe_connector
from secintegrate.runner import RunResult, run_connector
from secintegrate.security.cipher import AesGcmCipher
from secintegrate.security.keybackends import InMemoryKeyBackend
from secintegrate.security.master_key import MasterKeyProvider
from secintegrate.security.repository import SqliteSecretRepository
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database

BASE = "https://api.example.test"
FAKE_KEY = "sim-" + "key-0000"
RUNAWAY_LIMIT = 400  # a run that needs more requests than this is treated as never ending
LONG_WAIT_SECONDS = 600


class Runaway(Exception):
    """Raised by the fake server when a run keeps asking for pages forever."""


@dataclass
class World:
    requests: list[httpx.Request] = field(default_factory=list)
    runaway: bool = False


@dataclass
class Run:
    result: RunResult | None
    world: World
    sleeps: list[float]
    events: int
    quarantined: int
    cursor: str | None
    status: str
    probe_ok: bool | None = None
    changes: list[StateChange] = field(default_factory=list)

    @property
    def requests(self) -> int:
        return len(self.world.requests)

    def describe(self) -> str:
        r = self.result
        what = f"{r.status}/{r.category.value}" if r and r.category else (r.status if r else "probe")
        waited = f"{len(self.sleeps)} waits ({sum(self.sleeps):.0f}s)" if self.sleeps else "no waits"
        return f"{what} | {self.requests} requests | {waited} | {self.events} saved"


class Notes:
    def __init__(self) -> None:
        self.changes: list[StateChange] = []

    def notify(self, change: StateChange) -> None:
        self.changes.append(change)


def records(n: int, **over: Any) -> list[dict[str, Any]]:
    return [{"id": f"R{i}", "ts": "2026-01-01T00:00:00Z", "sev": "high", "updated": "2026-02-01T00:00:00Z", **over}
            for i in range(n)]


def reply(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(data).encode(), headers={"content-type": "application/json",
                                                                              **(headers or {})})


def build_cfg(**over: Any) -> ConnectorConfig:
    auth = over.pop("auth", {"type": "bearer", "secret": "SIM_KEY"})
    endpoint: dict[str, Any] = {
        "name": "items", "path": "/items", "records_path": over.pop("records_path", ""),
        "mapping": {"target": "event", "fields": {
            "id": {"from": "id", "required": True},
            "timestamp": {"from": "ts", "transform": "iso8601", "required": True},
            "severity": {"from": "sev", "default": "unknown"},
        }},
    }
    for key in ("pagination", "incremental"):
        if key in over:
            endpoint[key] = over.pop(key)
    data: dict[str, Any] = {"connector": "sim", "source": "sim", "schedule": "0 * * * *", "base_url": BASE,
                            "auth": auth, "endpoints": [endpoint]}
    data.update(over)
    return ConnectorConfig.model_validate(data)


Handler = Callable[[httpx.Request, World], httpx.Response]


def execute(handler: Handler, run_probe: bool = False, **cfg_kwargs: Any) -> Run:
    world = World()
    notes = Notes()
    sleeps: list[float] = []

    def serve(request: httpx.Request) -> httpx.Response:
        world.requests.append(request)
        if len(world.requests) >= RUNAWAY_LIMIT:
            world.runaway = True
            raise Runaway("the run never ended")
        return handler(request, world)

    transport = httpx.MockTransport(serve)
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "sim.db")
        repo = SqliteSecretRepository(":memory:")
        vault = SecretVault(MasterKeyProvider(InMemoryKeyBackend()), AesGcmCipher(), repo)
        vault.store("SIM_KEY", FAKE_KEY)
        cfg = build_cfg(**cfg_kwargs)
        result: RunResult | None = None
        probe_ok: bool | None = None
        if run_probe:
            probe_connector(cfg, db, vault, notes, sleeps.append, transport)
            latest = db.latest_probe("sim")
            probe_ok = bool(latest["ok"]) if latest else None
        else:
            result = run_connector(cfg, db, vault, notes, sleep=sleeps.append, transport=transport)
        conn = db.get_connection("sim") or {}
        run = Run(result, world, sleeps, db.count("events"), db.count_rows("quarantine", "sim"),
                  db.get_cursor("sim", "items"), str(conn.get("status")), probe_ok, notes.changes)
        repo.close()
    return run


# --- scenario registry ---------------------------------------------------------------------------------
@dataclass
class Scenario:
    group: str
    name: str
    should: str
    run: Callable[[], tuple[Run, str | None]]


SCENARIOS: list[Scenario] = []


def scenario(group: str, name: str, should: str) -> Callable[[Callable[[], tuple[Run, str | None]]], Any]:
    def register(fn: Callable[[], tuple[Run, str | None]]) -> Any:
        SCENARIOS.append(Scenario(group, name, should, fn))
        return fn
    return register


def expect(run: Run, ok: bool, problem: str) -> tuple[Run, str | None]:
    return run, None if ok else problem


def failed_as(run: Run, category: str) -> bool:
    return bool(run.result and run.result.status == "failed" and run.result.category
                and run.result.category.value == category)


G1 = "1. API errors"


@scenario(G1, "healthy API (control)", "succeed with 3 records")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply(records(3)))
    return expect(run, bool(run.result and run.result.status == "success" and run.events == 3), "control failed")


@scenario(G1, "401 unauthorised", "fail once as auth_failed, no retry")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({"message": "Bad credentials"}, 401))
    return expect(run, failed_as(run, "auth_failed") and run.requests == 1 and not run.sleeps, "retried or misclassified")


@scenario(G1, "403 permission denied (not a bad key)", "fail as auth_failed (documented: 401 and 403 are treated alike)")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({"message": "Resource not accessible"}, 403))
    return expect(run, failed_as(run, "auth_failed") and run.requests == 1, "unexpected handling of 403")


@scenario(G1, "403 that is really a rate limit (GitHub style)", "wait, then succeed")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        if len(w.requests) == 1:
            return reply({"message": "rate limit"}, 403, {"retry-after": "2", "x-ratelimit-remaining": "0"})
        return reply(records(2))
    run = execute(handler)
    return expect(run, bool(run.result and run.result.status == "success") and run.sleeps == [2.0],
                  "did not treat the 403 as a rate limit")


@scenario(G1, "404 not found", "fail once as not_found")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 404))
    return expect(run, failed_as(run, "not_found") and run.requests == 1, "wrong handling of 404")


@scenario(G1, "429 with Retry-After: 2", "wait 2 seconds, then succeed")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 429, {"retry-after": "2"}) if len(w.requests) == 1 else reply(records(1)))
    return expect(run, bool(run.result and run.result.status == "success") and run.sleeps == [2.0], "wrong wait")


@scenario(G1, "429 with an HTTP-date Retry-After", "wait about 2 seconds, then succeed")
def _() -> tuple[Run, str | None]:
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=3), usegmt=True)
    run = execute(lambda r, w: reply({}, 429, {"retry-after": when}) if len(w.requests) == 1 else reply(records(1)))
    return expect(run, bool(run.result and run.result.status == "success") and 0 <= sum(run.sleeps) <= 4,
                  "did not understand the date form")


@scenario(G1, "429 without any Retry-After", "wait the 30 second default, then succeed")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 429) if len(w.requests) == 1 else reply(records(1)))
    return expect(run, run.sleeps == [30.0], "default wait not applied")


@scenario(G1, "429 asking to wait an hour (Retry-After: 3600)", "not freeze the scheduler for hours")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 429, {"retry-after": "3600"}))
    return expect(run, sum(run.sleeps) <= LONG_WAIT_SECONDS,
                  f"BLIND SPOT: would sleep {sum(run.sleeps) / 3600:.1f} hours inside one run, blocking that connector")


@scenario(G1, "500 once, then fine", "retry after 1s and succeed")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 500) if len(w.requests) == 1 else reply(records(2)))
    return expect(run, bool(run.result and run.result.status == "success") and run.sleeps == [1.0], "no retry")


@scenario(G1, "503 saying Retry-After: 120", "honour the provider's 120 second request")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 503, {"retry-after": "120"}) if len(w.requests) == 1 else reply(records(1)))
    return expect(run, bool(run.sleeps) and run.sleeps[0] >= 120,
                  "INCONSISTENCY: Retry-After is honoured on 429 but ignored on 503 (retried after 1s)")


@scenario(G1, "502 forever", "retry 1s, 2s, 4s, then fail as server_error")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 502))
    return expect(run, failed_as(run, "server_error") and run.sleeps == [1.0, 2.0, 4.0], "wrong retry schedule")


@scenario(G1, "connection refused", "retry, then fail as network")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        raise httpx.ConnectError("refused", request=r)
    run = execute(handler)
    return expect(run, failed_as(run, "network") and run.requests == 4, "wrong handling")  # noqa: PLR2004


@scenario(G1, "response takes too long (read timeout)", "retry, then fail as network")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=r)
    run = execute(handler)
    return expect(run, failed_as(run, "network"), "timeout not classified as network")


@scenario(G1, "422 unprocessable", "fail once as client_error")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 422))
    return expect(run, failed_as(run, "client_error") and run.requests == 1, "wrong handling")


G2 = "2. Odd successful replies"


@scenario(G2, "200 with invalid JSON", "fail (unknown), keep running")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: httpx.Response(200, content=b"<html>oops</html>"))
    return expect(run, failed_as(run, "unknown"), "wrong handling")


@scenario(G2, "200 with an empty body", "succeed with 0 records (nothing new)")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: httpx.Response(200, content=b""))
    return expect(run, bool(run.result and run.result.status == "success"),
                  "INCONSISTENCY: an empty reply is reported as an error, an empty list as success")


@scenario(G2, "204 No Content", "succeed with 0 records")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: httpx.Response(204))
    return expect(run, bool(run.result and run.result.status == "success"),
                  "INCONSISTENCY: 204 No Content (a normal 'nothing new') is reported as an error")


@scenario(G2, "200 with JSON null", "succeed with 0 records")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: httpx.Response(200, content=b"null"))
    return expect(run, bool(run.result and run.result.status == "success"), "null body reported as an error")


@scenario(G2, "200 whose body is an error message", "fail, never report success")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({"message": "Bad credentials"}))
    return expect(run, bool(run.result and run.result.status == "failed"), "an error hidden in a 200 counted as success")


G3 = "3. Paging that never ends or misleads"


@scenario(G3, "Link header points back to the same page", "stop quickly with an error")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply(records(2), headers={"link": f'<{BASE}/items?page=2>; rel="next"'}),
                  pagination={"type": "link_header"})
    return expect(run, run.requests < 50 and bool(run.result and run.result.status == "failed"),  # noqa: PLR2004
                  f"BLIND SPOT: never stops ({run.requests}+ requests, I cut it off)")


@scenario(G3, "Link header points at a different host", "never send the key to another host")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        if r.url.host != "api.example.test":
            return reply([])
        return reply(records(1), headers={"link": '<https://evil.example.test/steal>; rel="next"'})
    run = execute(handler, pagination={"type": "link_header"})
    leaked = [q for q in run.world.requests if q.url.host != "api.example.test" and "authorization" in q.headers]
    return expect(run, not leaked, "SECURITY BLIND SPOT: the bearer token was sent to evil.example.test")


@scenario(G3, "Link header with a relative URL", "follow it and fetch page 2")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        if "page=2" in str(r.url):
            return reply(records(2, id="LATE"))
        return reply(records(1), headers={"link": '</items?page=2>; rel="next"'})
    run = execute(handler, pagination={"type": "link_header"})
    return expect(run, bool(run.result and run.result.status == "success") and run.requests == 2,  # noqa: PLR2004
                  "BLIND SPOT: relative next links break the run (reported as an unknown error)")


@scenario(G3, "cursor token never changes", "stop quickly with an error")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({"data": records(2), "next": "same-token"}), records_path="data",
                  pagination={"type": "cursor", "param": "after", "next_path": "next"})
    return expect(run, run.requests < 50 and bool(run.result and run.result.status == "failed"),  # noqa: PLR2004
                  f"BLIND SPOT: never stops ({run.requests}+ requests, I cut it off)")


@scenario(G3, "page-number API ignores the page number", "stop quickly with an error")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply(records(2)), pagination={"type": "page_number", "param": "page"})
    return expect(run, run.requests < 50 and bool(run.result and run.result.status == "failed"),  # noqa: PLR2004
                  f"BLIND SPOT: never stops ({run.requests}+ requests, I cut it off)")


@scenario(G3, "offset API with no total ignores the offset", "stop quickly with an error")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply(records(2)),
                  pagination={"type": "offset", "start_param": "offset", "limit_param": "limit", "limit": 2})
    return expect(run, run.requests < 50 and bool(run.result and run.result.status == "failed"),  # noqa: PLR2004
                  f"BLIND SPOT: never stops ({run.requests}+ requests, I cut it off)")


@scenario(G3, "page 2 fails for good (500)", "keep page 1, fail, do not advance the cursor")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        if "page=2" in str(r.url):
            return reply({}, 500)
        return reply(records(3), headers={"link": f'<{BASE}/items?page=2>; rel="next"'})
    run = execute(handler, pagination={"type": "link_header"},
                  incremental={"cursor_field": "updated", "param": "since", "initial": "2026-01-01"})
    return expect(run, failed_as(run, "server_error") and run.events == 3 and run.cursor is None,  # noqa: PLR2004
                  "partial data or cursor handled wrongly")


G4 = "4. Data that can quietly go wrong"


@scenario(G4, "one record dated year 9999", "not let it push the sync cursor into the future")
def _() -> tuple[Run, str | None]:
    data = records(2) + [{"id": "BAD", "ts": "2026-01-01T00:00:00Z", "sev": "low", "updated": "9999-12-31T00:00:00Z"}]
    run = execute(lambda r, w: reply(data),
                  incremental={"cursor_field": "updated", "param": "since", "initial": "2026-01-01"})
    future = run.cursor is not None and run.cursor > (datetime.now(UTC) + timedelta(days=2)).strftime("%Y-%m-%d")
    return expect(run, not future, f"BLIND SPOT: cursor became {run.cursor}, so every newer record is skipped forever")


@scenario(G4, "the same id appears twice on a page", "store it once")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply(records(1) + records(1) + records(2, id="OTHER")[:1]))
    return expect(run, run.events == 2, "duplicate ids stored twice")  # noqa: PLR2004


@scenario(G4, "all records lack the required id", "fail as schema_changed")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply([{"ts": "2026-01-01T00:00:00Z"} for _ in range(3)]))
    return expect(run, failed_as(run, "schema_changed"), "wrong handling")


@scenario(G4, "6,000 different bad records in one run", "cap how many are stored")
def _() -> tuple[Run, str | None]:
    bad = [{"ts": "2026-01-01T00:00:00Z", "n": i, "id": None} for i in range(6000)]
    mixed = bad + records(2)
    run = execute(lambda r, w: reply(mixed))
    return expect(run, run.quarantined <= 5000,  # noqa: PLR2004
                  f"BLIND SPOT: {run.quarantined} bad records stored, with no upper limit")


G5 = "5. Secrets and monitoring"


@scenario(G5, "redirect to another host (API-key header)", "never send the key to the other host")
def _() -> tuple[Run, str | None]:
    def handler(r: httpx.Request, w: World) -> httpx.Response:
        if r.url.host != "api.example.test":
            return reply([])
        return httpx.Response(302, headers={"location": "https://other.example.test/items"})
    run = execute(handler, auth={"type": "api_key_header", "header": "apiKey", "secret": "SIM_KEY"})
    leaked = [q for q in run.world.requests if q.url.host != "api.example.test" and "apikey" in q.headers]
    return expect(run, not leaked, "SECURITY BLIND SPOT: the API key header followed a redirect to other.example.test")


@scenario(G5, "health probe gets 429", "not mark a reachable service as unhealthy")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: reply({}, 429), run_probe=True, probe={"path": "/ping"})
    return expect(run, run.probe_ok is True,
                  "INCONSISTENCY: a probe 429 proves the service and key work, yet it is shown as a failure")


@scenario(G5, "health probe gets 204 (expects 200)", "report a failure")
def _() -> tuple[Run, str | None]:
    run = execute(lambda r, w: httpx.Response(204), run_probe=True, probe={"path": "/ping"})
    return expect(run, run.probe_ok is False, "unexpected status accepted")


@scenario(G5, "10 failures in a row after a good run", "send exactly one notification")
def _() -> tuple[Run, str | None]:
    count = {"n": 0}
    notes = Notes()

    def handler(r: httpx.Request, w: World) -> httpx.Response:
        count["n"] += 1
        return reply(records(1)) if count["n"] == 1 else reply({}, 404)

    world = World()
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "s.db")
        repo = SqliteSecretRepository(":memory:")
        vault = SecretVault(MasterKeyProvider(InMemoryKeyBackend()), AesGcmCipher(), repo)
        vault.store("SIM_KEY", FAKE_KEY)
        transport = httpx.MockTransport(lambda req: (world.requests.append(req), handler(req, world))[1])
        cfg = build_cfg()
        for _ in range(11):
            run_connector(cfg, db, vault, notes, sleep=lambda s: None, transport=transport)
        repo.close()
    run = Run(None, world, [], 0, 0, None, "failing", None, notes.changes)
    return expect(run, len(notes.changes) == 1, f"{len(notes.changes)} notifications for one outage")


def main() -> int:
    problems: list[tuple[str, str]] = []
    group = ""
    for item in SCENARIOS:
        if item.group != group:
            group = item.group
            print(f"\n{group}")
        run, problem = item.run()
        mark = "OK     " if problem is None else "PROBLEM"
        print(f"  [{mark}] {item.name}")
        print(f"            should: {item.should}")
        print(f"            did:    {run.describe()}")
        if problem:
            print(f"            >>> {problem}")
            problems.append((item.name, problem))
    print(f"\n{len(SCENARIOS)} scenarios, {len(SCENARIOS) - len(problems)} behaved as designed, {len(problems)} problems.")
    for name, problem in problems:
        print(f"  - {name}: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
