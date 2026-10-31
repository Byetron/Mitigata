"""A small, MCP-style toolbox: named tools with descriptions and input schemas, called through one registry.

This is not the Model Context Protocol itself (no server, no model). It borrows the useful idea: every action Hermes
can take on an integration is a named tool with a declared input shape, a result, and a record of who called it.
Read-only tools and "safe" repairs may be run automatically; anything else needs a person (caller="user").
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from .classify import FailureCategory
from .config.schema import ConnectorConfig
from .diagnose import (
    CleanedVault,
    Resolver,
    TlsCheck,
    default_resolver,
    default_tls_check,
    diagnose,
    inspect_secrets,
    live_findings,
)
from .health import refresh_connection
from .notify import Notifier
from .probe import _send_probe
from .runner import run_connector
from .security.vault import SecretVault
from .storage.db import Database

logger = logging.getLogger(__name__)


@dataclass
class ToolContext:
    cfg: ConnectorConfig
    db: Database
    vault: SecretVault
    notifier: Notifier
    transport: httpx.BaseTransport | None = None
    sleep: Callable[[float], None] = time.sleep
    resolver: Resolver = default_resolver
    tls_check: TlsCheck = default_tls_check


@dataclass
class ToolResult:
    ok: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    run: Callable[[ToolContext, dict[str, Any]], ToolResult]
    safe: bool  # True: may be run automatically. False: only when a person asks.
    changes_state: bool


NO_ARGS: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def list_tools(self) -> list[dict[str, Any]]:
        """The catalogue, shaped like an MCP `tools/list` reply."""
        return [{"name": t.name, "description": t.description, "inputSchema": t.input_schema,
                 "annotations": {"readOnlyHint": not t.changes_state, "autoSafe": t.safe}}
                for t in self._tools.values()]

    def call(self, name: str, ctx: ToolContext, args: dict[str, Any] | None = None, caller: str = "user") -> ToolResult:
        tool = self._tools.get(name)
        arguments = args or {}
        if tool is None:
            return self._log(ctx, name, caller, arguments, ToolResult(False, f"there is no tool called {name}"))
        if not tool.safe and caller != "user":
            return self._log(ctx, name, caller, arguments,
                             ToolResult(False, f"{name} is not allowed to run automatically"))
        extra = set(arguments) - set(tool.input_schema.get("properties", {}))
        if extra:
            return self._log(ctx, name, caller, arguments,
                             ToolResult(False, f"unexpected input: {', '.join(sorted(extra))}"))
        try:
            result = tool.run(ctx, arguments)
        except Exception as exc:  # a tool must never take the caller down; the failure is the result
            logger.warning("tool %s failed with %s", name, type(exc).__name__)
            result = ToolResult(False, f"{name} failed unexpectedly ({type(exc).__name__})")
        return self._log(ctx, name, caller, arguments, result)

    @staticmethod
    def _log(ctx: ToolContext, name: str, caller: str, arguments: dict[str, Any], result: ToolResult) -> ToolResult:
        ctx.db.add_tool_call(name, ctx.cfg.connector, caller, json.dumps(arguments, default=str), result.ok,
                             result.message)
        return result


# --- the tools --------------------------------------------------------------------------------------------------------
def _diagnose(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    d = diagnose(ctx.cfg, ctx.db, ctx.vault, resolver=ctx.resolver, tls_check=ctx.tls_check,
                 transport=ctx.transport, sleep=ctx.sleep)
    return ToolResult(d.verdict == "healthy", d.summary, {"verdict": d.verdict,
                                                           "root_cause": d.root_cause.code if d.root_cause else ""})


def _recent_requests(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    rows = ctx.db.recent_requests(ctx.cfg.connector, int(args.get("limit", 20)))
    bad = sum(1 for r in rows if r["status"] is None or r["status"] >= 400)  # noqa: PLR2004
    return ToolResult(True, f"{len(rows)} recent request(s), {bad} failed", {"requests": len(rows), "failed": bad})


def _check_credential(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    findings, cleaned = inspect_secrets(ctx.cfg, ctx.vault)
    errors = [f for f in findings if f.level == "error"]
    if not errors:
        return ToolResult(True, "the stored key(s) look clean")
    return ToolResult(False, "; ".join(f.title for f in errors), {"fixable": sorted(cleaned)})


def _reprobe(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    if ctx.cfg.probe is None:
        return ToolResult(False, "this connector has no health check to run")
    result = _send_probe(ctx.cfg, ctx.vault, ctx.sleep, ctx.transport, ctx.db.recorder(ctx.cfg.connector))
    ctx.db.add_probe(ctx.cfg.connector, result.ok, result.category.value if result.category else None,
                     result.status, result.latency_ms)
    if result.ok:
        return ToolResult(True, f"the API answered (HTTP {result.status})", {"status": result.status})
    return ToolResult(False, f"still failing: {result.category.value if result.category else 'unknown'}",
                      {"category": result.category.value if result.category else ""})


def _clean_secret(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Store the cleaned form of a key, but only after the API accepts it. Never changes the key's real characters."""
    _, cleaned = inspect_secrets(ctx.cfg, ctx.vault)
    if not cleaned:
        return ToolResult(False, "no stored key has damage that can be removed safely")
    trial = live_findings(ctx.cfg, ctx.db, CleanedVault(ctx.vault, cleaned), ctx.transport, ctx.sleep)
    if any(f.level == "error" for f in trial):
        return ToolResult(False, "the API still refuses the key after cleaning, so nothing was changed; "
                                 "it needs to be replaced")
    for name, value in cleaned.items():
        ctx.vault.store(name, value)
    return ToolResult(True, f"cleaned and re-stored {', '.join(sorted(cleaned))} after the API accepted it",
                      {"names": sorted(cleaned)})


def _resume(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    conn = ctx.db.get_connection(ctx.cfg.connector) or {}
    if not conn.get("paused"):
        return ToolResult(True, "the connector was not paused")
    probe = _reprobe(ctx, {})
    if not probe.ok:
        return ToolResult(False, f"not resumed: {probe.message}")
    refresh_connection(ctx.db, ctx.notifier, ctx.cfg.connector, paused=0, consecutive_failures=0, message=None)
    return ToolResult(True, "the connector was resumed after a passing check")


def _rerun(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    if not ctx.cfg.enabled:
        return ToolResult(False, "not run: the connector is disabled")
    conn = ctx.db.get_connection(ctx.cfg.connector) or {}
    if conn.get("paused"):
        return ToolResult(False, "not run: the connector is paused")
    r = run_connector(ctx.cfg, ctx.db, ctx.vault, ctx.notifier, sleep=ctx.sleep, transport=ctx.transport)
    if r.status == "success":
        return ToolResult(True, f"a run succeeded ({r.records_ok} records)", {"records": r.records_ok})
    category = r.category.value if r.category else FailureCategory.UNKNOWN.value
    return ToolResult(False, f"the run failed: {category}", {"category": category})


def _requarantine(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    from .autoheal import reprocess_quarantine  # noqa: PLC0415 - kept local to avoid an import cycle

    freed = reprocess_quarantine(ctx.cfg, ctx.db)
    return ToolResult(True, f"{freed} set-aside record(s) now map and were saved", {"released": freed})


def default_registry() -> ToolRegistry:
    reg = ToolRegistry()
    limit = {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200}},
             "additionalProperties": False}
    for tool in (
        Tool("diagnose", "Inspect the config, keys, network and live API, and say what is wrong.", NO_ARGS,
             _diagnose, safe=True, changes_state=False),
        Tool("recent_requests", "Count recent API requests and how many failed.", limit,
             _recent_requests, safe=True, changes_state=False),
        Tool("check_credential", "Look for hidden characters or damage in the stored key, without showing it.",
             NO_ARGS, _check_credential, safe=True, changes_state=False),
        Tool("reprobe", "Send one health-check request to the API.", NO_ARGS, _reprobe, safe=True,
             changes_state=True),
        Tool("clean_secret", "Remove copy-paste damage from a stored key, only if the API then accepts it.",
             NO_ARGS, _clean_secret, safe=True, changes_state=True),
        Tool("resume", "Lift a pause, only after a health check passes.", NO_ARGS, _resume, safe=True,
             changes_state=True),
        Tool("rerun", "Run the connector once now.", NO_ARGS, _rerun, safe=True, changes_state=True),
        Tool("reprocess_quarantine", "Retry the records that were set aside, with the current mapping.", NO_ARGS,
             _requarantine, safe=True, changes_state=True),
    ):
        reg.register(tool)
    return reg
