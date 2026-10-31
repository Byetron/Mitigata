"""B2: config validation with path-specific, line-numbered messages."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .loader import config_files, env_refs
from .schema import ConnectorConfig

_SECRET_PATHS = {"secret", "username_env"}


@dataclass
class Issue:
    file: str
    line: int
    path: str
    message: str

    def __str__(self) -> str:
        where = f"{self.file}:{self.line}"
        return f"{where} {self.path}: {self.message}" if self.path else f"{where} {self.message}"


def format_path(loc: tuple) -> str:
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out


def find_line(node: yaml.Node | None, loc: tuple) -> int:
    """Walk the YAML node tree along loc; return the best 1-based line found."""
    line = node.start_mark.line + 1 if node is not None else 1
    for part in loc:
        if isinstance(node, yaml.MappingNode):
            hit = next(((k, v) for k, v in node.value if k.value == part), None)
            if hit is None:
                break
            line, node = hit[0].start_mark.line + 1, hit[1]
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value):
            node = node.value[part]
            line = node.start_mark.line + 1
        else:
            break
    return line


def _message(err: dict) -> str:
    kind, msg = err["type"], err["msg"]
    loc = err["loc"]
    show_input = not (set(map(str, loc)) & _SECRET_PATHS)
    got = ""
    if show_input and isinstance(err.get("input"), (str, int, float, bool)):
        got = f", got {err['input']!r}".replace("'", '"')
    if kind in ("int_parsing", "int_type"):
        return f"expected integer{got}"
    if kind in ("float_parsing", "float_type"):
        return f"expected number{got}"
    if kind in ("bool_parsing", "bool_type"):
        return f"expected boolean{got}"
    if kind == "string_type":
        return f"expected string{got}"
    if kind == "missing":
        return "field is required"
    if kind == "extra_forbidden":
        return "unknown field"
    if kind == "literal_error":
        return msg.replace("Input should be ", "must be ")
    return msg.removeprefix("Value error, ")


def validate_text(
    text: str,
    filename: str = "<config>",
    known_ids: set[str] | None = None,
    check_env: bool = True,
) -> tuple[ConnectorConfig | None, list[Issue]]:
    try:
        node = yaml.compose(text)
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        return None, [Issue(filename, line, "", f"invalid YAML: {getattr(exc, 'problem', exc)}")]
    if not isinstance(data, dict):
        return None, [Issue(filename, 1, "", "top level must be a mapping of connector settings")]

    issues: list[Issue] = []
    cfg: ConnectorConfig | None = None
    try:
        cfg = ConnectorConfig.model_validate(data)
    except ValidationError as exc:
        for err in exc.errors():
            loc = tuple(err["loc"])
            issues.append(Issue(filename, find_line(node, loc), format_path(loc), _message(err)))

    if check_env:
        issues += _env_issues(data, node, filename)
    if cfg and known_ids and cfg.connector in known_ids:
        issues.append(
            Issue(filename, find_line(node, ("connector",)), "connector",
                  f"connector {cfg.connector} is defined in two files")
        )
    issues.sort(key=lambda i: i.line)
    return cfg, issues


def _env_issues(data: dict, node: yaml.Node, filename: str) -> list[Issue]:
    """Report env var NAMES that are unset. Values are never read into messages."""
    out: list[Issue] = []
    auth = data.get("auth") if isinstance(data.get("auth"), dict) else {}
    for key in ("secret", "username_env"):
        name = auth.get(key)
        if isinstance(name, str) and name.isidentifier() and name.isupper() and not os.environ.get(name):
            out.append(Issue(filename, find_line(node, ("auth", key)), f"auth.{key}", f"{name} is not set in .env"))
    refs: list[tuple[tuple, str]] = [(("base_url",), data.get("base_url"))]
    for i, ep in enumerate(data.get("endpoints") or []):
        if isinstance(ep, dict) and isinstance(ep.get("vars"), dict):
            refs += [(("endpoints", i, "vars", k), v) for k, v in ep["vars"].items()]
    for loc, value in refs:
        for name in env_refs(value):
            if not os.environ.get(name):
                out.append(Issue(filename, find_line(node, loc), format_path(loc), f"{name} is not set in .env"))
    return out


def validate_paths(paths: list[Path], check_env: bool = True) -> list[Issue]:
    issues: list[Issue] = []
    seen: dict[str, Path] = {}
    for p in paths:
        text = p.read_text(encoding="utf-8")
        cfg, found = validate_text(text, str(p), set(seen), check_env)
        issues += found
        if cfg and cfg.connector not in seen:
            seen[cfg.connector] = p
    return issues


def validate_dir(directory: str | Path, check_env: bool = True) -> list[Issue]:
    return validate_paths(config_files(directory), check_env)


def existing_ids(directory: str | Path) -> set[str]:
    ids: set[str] = set()
    for f in config_files(directory):
        try:
            data: Any = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and isinstance(data.get("connector"), str):
            ids.add(data["connector"])
    return ids
