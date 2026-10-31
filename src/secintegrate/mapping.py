"""Dot-path resolution and mapping of source records to the common schema (FR-5)."""
from __future__ import annotations

import re
from typing import Any

from .transforms import TRANSFORMS

_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


class MappingError(Exception):
    """The record cannot be mapped; it goes to quarantine."""


def parse_path(path: str) -> list[str | int]:
    return [m.group(1) if m.group(1) is not None else int(m.group(2)) for m in _TOKEN.finditer(path)]


def get_path(obj: Any, path: str) -> tuple[bool, Any]:
    """Return (found, value) for a path such as 'cve.descriptions[0].value'."""
    cur = obj
    for tok in parse_path(path):
        if isinstance(tok, int):
            if not isinstance(cur, list) or tok >= len(cur):
                return False, None
            cur = cur[tok]
        else:
            if not isinstance(cur, dict) or tok not in cur:
                return False, None
            cur = cur[tok]
    return True, cur


def apply_mapping(record: Any, fields: dict[str, Any]) -> dict[str, Any]:
    """Apply FieldRule objects to one record. Raises MappingError on any failure."""
    if not isinstance(record, dict):
        raise MappingError("record is not an object")
    out: dict[str, Any] = {}
    for name, rule in fields.items():
        given = rule.model_fields_set
        if "const" in given:
            out[name] = rule.const
            continue
        value = None
        if rule.from_ is not None:
            found, value = get_path(record, rule.from_)
            if not found:
                value = None
        if value is None:
            if rule.required:
                raise MappingError(f"required field missing: {rule.from_ or name}")
            if "default" in given:
                out[name] = rule.default
                continue
            if rule.from_ is None:
                out[name] = None
                continue
            raise MappingError(f"missing value without default: {rule.from_}")
        if rule.transform:
            try:
                value = TRANSFORMS[rule.transform](value)
            except Exception as exc:  # any transform failure quarantines the record
                raise MappingError(f"transform {rule.transform} failed for {name}: {exc}") from exc
        out[name] = value
    return out
