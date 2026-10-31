"""Auto-repair: diagnose a broken integration, run the safe tools that fit the cause, check, and report.

Only tools marked safe are used. Anything that needs a person (a missing key, a wrong address, a changed field name)
is not guessed at: it is handed over with the exact fix. One pass, each tool at most once, so it can never loop.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .diagnose import Diagnosis
from .notify import StateChange
from .storage.db import now_iso
from .tools import ToolContext, ToolRegistry, ToolResult, default_registry

# cause (a finding code) -> the safe tools to try, in order
PLANS: dict[str, tuple[str, ...]] = {
    "secret_dirty": ("clean_secret", "resume", "rerun"),
    "connector_paused": ("resume", "rerun"),
    "endpoint_server_error": ("reprobe", "resume", "rerun"),
    "network_unreachable": ("reprobe", "resume", "rerun"),
    "endpoint_rate_limited": ("reprobe", "rerun"),
    "endpoint_slow": ("reprobe",),
    "quarantine_backlog": ("reprocess_quarantine",),
}


@dataclass
class Step:
    tool: str
    ok: bool
    message: str


@dataclass
class RepairReport:
    connector: str
    at: str
    cause: str
    before: str
    after: str
    steps: list[Step] = field(default_factory=list)
    needs_human: str = ""  # empty when nothing is left for a person to do

    @property
    def fixed(self) -> bool:
        return self.before != "healthy" and self.after == "healthy"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def repair(ctx: ToolContext, registry: ToolRegistry | None = None, caller: str = "auto") -> RepairReport:
    reg = registry or default_registry()
    connector = ctx.cfg.connector
    previous = ctx.db.get_diagnosis(connector)
    before = _diagnose(ctx, reg, caller)
    cause = before.root_cause.code if before.root_cause else ""
    report = RepairReport(connector, now_iso(), cause, before.verdict, before.verdict)
    if before.verdict == "healthy":
        return report

    codes = {f.code for f in before.findings if f.level in ("warn", "error")}
    plan: list[str] = []
    for code in (cause, *sorted(codes)):  # the main cause first, then any other fixable problem
        for name in PLANS.get(code, ()):
            if name not in plan:
                plan.append(name)
    for name in plan:
        result: ToolResult = reg.call(name, ctx, {}, caller)
        report.steps.append(Step(name, result.ok, result.message))
        if not result.ok and name in ("clean_secret", "reprobe"):
            break  # the repair did not hold, so later steps would only repeat the failure

    after = _diagnose(ctx, reg, caller)
    report.after = after.verdict
    if after.verdict != "healthy" and after.root_cause is not None:
        fix = after.root_cause.fix or "See the diagnosis for details."
        report.needs_human = f"{after.root_cause.title}. {fix}"

    _notify(ctx, report, previous["verdict"] if previous else None, after)
    return report


def _diagnose(ctx: ToolContext, reg: ToolRegistry, caller: str) -> Diagnosis:
    reg.call("diagnose", ctx, {}, caller)
    saved = ctx.db.get_diagnosis(ctx.cfg.connector)
    assert saved is not None  # noqa: S101 - the diagnose tool always saves
    return Diagnosis.from_json(saved["report"])


def _notify(ctx: ToolContext, report: RepairReport, previous_verdict: str | None, after: Diagnosis) -> None:
    """Tell the user once per outcome: recovered by auto-repair, or needs a person."""
    if report.fixed:
        message = "Fixed automatically: " + "; ".join(s.message for s in report.steps if s.ok)
        change = StateChange(report.connector, "failing", "healthy", message, report.at)
    elif report.needs_human and previous_verdict != after.verdict:
        change = StateChange(report.connector, previous_verdict or "unknown", "failing",
                             "Needs a person: " + report.needs_human, report.at)
    else:
        return
    ctx.notifier.notify(change)
