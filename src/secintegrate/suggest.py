"""Suggested fixes for a connector's YAML, shown in the editor.

Each suggestion is a small, exact text change the user can apply to the editor with one click and then review and save.
Nothing is applied automatically, and nothing here touches the saved file or any key.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml

from .diagnose import Diagnosis

PROBE_INTERVAL = 15


@dataclass(frozen=True)
class Suggestion:
    title: str
    why: str
    kind: str  # "replace": swap old for new everywhere; "append": add new at the end of the file
    old: str
    new: str


def _parse(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _first_path(data: dict[str, Any]) -> str:
    endpoints = data.get("endpoints")
    first = endpoints[0] if isinstance(endpoints, list) and endpoints and isinstance(endpoints[0], dict) else {}
    path = str(first.get("path") or "/")
    return "/" if "{" in path else path


def suggest_fixes(text: str, diagnosis: Diagnosis | None = None) -> list[Suggestion]:
    data = _parse(text)
    if not data:
        return []
    out: list[Suggestion] = []

    connector, source = str(data.get("connector") or ""), str(data.get("source") or "")
    prefix = connector.split("_", maxsplit=1)[0]
    if source and prefix and source != prefix and sorted(source) == sorted(prefix) and f"source: {source}" in text:
        out.append(Suggestion(
            "Source label looks mistyped",
            f"`{source}` has the same letters as `{prefix}`, the start of the connector id.",
            "replace", f"source: {source}", f"source: {prefix}"))

    if "probe" not in data:
        path = _first_path(data)
        out.append(Suggestion(
            "Add a health check",
            "Without a probe the connection is not checked between runs. Pick a lighter path if the API has one.",
            "append", "", f"probe:\n  path: {path}\n  interval_minutes: {PROBE_INTERVAL}\n"))

    for finding in diagnosis.findings if diagnosis else []:
        ev = finding.evidence
        if finding.code == "field_missing" and ev.get("suggestion") and ev.get("source_path"):
            old, new = f"from: {ev['source_path']}", f"from: {ev['suggestion']}"
            if old in text:
                out.append(Suggestion(f"Field `{ev['source_path']}` was not in the reply",
                                      f"The reply has `{ev['suggestion']}`.", "replace", old, new))
        elif finding.code == "records_path_missing" and ev.get("suggestion"):
            current = str(data.get("endpoints", [{}])[0].get("records_path") or "")
            old = f"records_path: {current}"
            if current and old in text:
                out.append(Suggestion("The records list is not where the config says",
                                      f"The reply has `{ev['suggestion']}`.", "replace", old,
                                      f"records_path: {ev['suggestion']}"))
        elif finding.code == "endpoint_rate_limited" and "rate_limit" not in data:
            out.append(Suggestion("Slow down requests", "The API is limiting requests; this spaces them out.",
                                  "append", "", "rate_limit:\n  max_requests: 30\n  per_seconds: 60\n"))
    return out
