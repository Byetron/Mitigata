"""Remediation table (brief 2.4): one fixed action and one fixed message per category. No ML.

Messages are filled from structured fields only, never from response bodies, headers or exceptions.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .classify import FailureCategory


class Action(StrEnum):
    PAUSE_AFTER_TWO_FAILURES = "pause_after_two_failures"
    STOP_RUN = "stop_run"
    WAIT_RETRY_AFTER = "wait_retry_after"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    QUARANTINE_PAGE_AND_STOP = "quarantine_page_and_stop"
    QUARANTINE_RECORD_AND_CONTINUE = "quarantine_record_and_continue"


@dataclass(frozen=True)
class Remediation:
    action: Action
    template: str | None


@dataclass
class MessageContext:
    """Structured facts a message may use. Nothing here comes from a response body."""

    env_name: str = ""
    path: str = ""
    host: str = ""
    field: str = ""
    status: int | None = None
    n: int = 0
    total: int = 0


REMEDIATION: dict[FailureCategory, Remediation] = {
    FailureCategory.AUTH_FAILED: Remediation(
        Action.PAUSE_AFTER_TWO_FAILURES,
        "Credential `{ENV_NAME}` was rejected. Run `secintegrate secret set {ENV_NAME}` with a valid key."),
    FailureCategory.NOT_FOUND: Remediation(
        Action.STOP_RUN, "Endpoint `{path}` returned 404. Check `base_url` and `path` in the config."),
    FailureCategory.RATE_LIMITED: Remediation(Action.WAIT_RETRY_AFTER, None),  # self-healing
    FailureCategory.SERVER_ERROR: Remediation(
        Action.RETRY_WITH_BACKOFF, "Provider is returning server errors. Check its status page."),
    FailureCategory.NETWORK: Remediation(
        Action.RETRY_WITH_BACKOFF, "Cannot reach `{host}`. Check network connectivity."),
    FailureCategory.SCHEMA_CHANGED: Remediation(
        Action.QUARANTINE_PAGE_AND_STOP,
        "Field `{field}` is missing from the response. The provider may have changed its API. "
        "Review the mapping."),
    FailureCategory.BAD_DATA: Remediation(
        Action.QUARANTINE_RECORD_AND_CONTINUE, "{n} of {total} records invalid in the last run."),
    FailureCategory.CLIENT_ERROR: Remediation(
        Action.STOP_RUN, "Provider rejected the request ({status}). Review the config."),
    FailureCategory.UNKNOWN: Remediation(Action.STOP_RUN, "Unexpected error. See logs for details."),
}

RATE_LIMIT_EXCEEDED = ("The provider kept rate-limiting requests (more than 5 waits in one run). "
                       "Lower the schedule frequency or the connector's rate limit.")


def human_message(category: FailureCategory, ctx: MessageContext) -> str | None:
    """The message shown on the health page, or None when the category is self-healing."""
    entry = REMEDIATION[category]
    if entry.template is None:
        return RATE_LIMIT_EXCEEDED if category is FailureCategory.RATE_LIMITED else None
    return entry.template.format(
        ENV_NAME=ctx.env_name, path=ctx.path, host=ctx.host, field=ctx.field,
        status=ctx.status if ctx.status is not None else "unknown", n=ctx.n, total=ctx.total,
    )
