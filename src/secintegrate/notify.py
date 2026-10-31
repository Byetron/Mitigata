"""State-change notifications (brief 2.6). Only transitions notify, never every failure."""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StateChange:
    connector: str
    old_status: str
    new_status: str
    message: str
    timestamp: str


class Notifier(Protocol):
    def notify(self, change: StateChange) -> None: ...


def should_notify(old: str, new: str) -> bool:
    """healthy -> degraded, healthy -> failing, anything -> paused, and recovery to healthy.

    A first successful run after `never_run` is not a recovery, so it stays quiet.
    """
    if old == new:
        return False
    if new == "paused":
        return True
    if new == "healthy":
        return old != "never_run"
    return old == "healthy" and new in ("degraded", "failing")


def describe(change: StateChange) -> str:
    return f"[{change.connector}] {change.new_status}: {change.message} ({change.timestamp})"


class LogNotifier:
    """Always on. Writes to the log file."""

    def notify(self, change: StateChange) -> None:
        logger.warning("state change %s -> %s: %s", change.old_status, change.new_status, describe(change))


class WebhookNotifier:
    """Posts to a Slack or Discord incoming webhook. The URL is a secret named NOTIFY_WEBHOOK_URL."""

    def __init__(self, get_url: Callable[[], str | None], timeout: float = 10.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        self._get_url = get_url
        self._timeout = timeout
        self._transport = transport

    def notify(self, change: StateChange) -> None:
        try:
            url = self._get_url()
            if not url:
                return
            text = describe(change)
            body = {  # connector, status, message, timestamp, and the same line for Slack (text) and Discord (content)
                "connector": change.connector, "status": change.new_status, "message": change.message,
                "timestamp": change.timestamp, "text": text, "content": text,
            }
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                client.post(url, json=body).raise_for_status()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("webhook notification failed: %s", type(exc).__name__)  # never log the URL


class CompositeNotifier:
    def __init__(self, notifiers: list[Notifier]) -> None:
        self._notifiers = notifiers

    def notify(self, change: StateChange) -> None:
        for notifier in self._notifiers:
            try:
                notifier.notify(change)
            except Exception as exc:
                logger.warning("notifier %s failed: %s", type(notifier).__name__, type(exc).__name__)
