"""The one validator used by the CLI and the web form (brief section 3)."""
from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import ValidationError

from .loader import config_files
from .schema import ENV_NAME_RE, ConnectorConfig

Severity = Literal["error", "warning"]
_SECRET_PATHS = {"secret", "username_env"}


@dataclass
class ValidationIssue:
    path: str
    line: int
    message: str
    severity: Severity = "error"
    file: str = ""

    def __str__(self) -> str:
        field = f" {self.path}:" if self.path else ""
        note = "" if self.severity == "error" else " (warning)"
        return f"{self.file}:{self.line}{field} {self.message}{note}"


Issue = ValidationIssue  # older name


def has_errors(issues: Collection[ValidationIssue]) -> bool:
    return any(i.severity == "error" for i in issues)


def format_path(loc: tuple[Any, ...]) -> str:
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out


def find_line(node: yaml.Node | None, loc: tuple[Any, ...]) -> int:
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


def _message(err: Any) -> str:
    kind, msg, loc = err["type"], err["msg"], err["loc"]
    show_input = not (set(map(str, loc)) & _SECRET_PATHS)
    got = ""
    if show_input and isinstance(err.get("input"), str | int | float | bool):
        got = f", got {err['input']!r}".replace("'", '"')
    simple = {
        "int_parsing": "expected integer", "int_type": "expected integer",
        "float_parsing": "expected number", "float_type": "expected number",
        "bool_parsing": "expected boolean", "bool_type": "expected boolean",
        "string_type": "expected string",
    }
    if kind in simple:
        return simple[kind] + got
    if kind == "missing":
        return "This field is required."
    if kind == "extra_forbidden":
        return "Unknown field."
    if kind == "literal_error":
        return str(msg).replace("Input should be ", "Must be ")
    return str(msg).removeprefix("Value error, ")


def validate_text(
    text: str,
    filename: str = "<config>",
    known_ids: Collection[str] | None = None,
    known_secrets: Collection[str] | None = None,
) -> tuple[ConnectorConfig | None, list[ValidationIssue]]:
    """Validate one config. `known_secrets` is the set of names in the vault (None skips that check)."""
    try:
        node = yaml.compose(text)
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        return None, [ValidationIssue("", line, f"Invalid YAML: {getattr(exc, 'problem', exc)}", file=filename)]
    if not isinstance(data, dict):
        return None, [ValidationIssue("", 1, "The file must be a mapping of connector settings.", file=filename)]

    issues: list[ValidationIssue] = []
    cfg: ConnectorConfig | None = None
    try:
        cfg = ConnectorConfig.model_validate(data)
    except ValidationError as exc:
        for err in exc.errors():
            loc = tuple(err["loc"])
            issues.append(ValidationIssue(format_path(loc), find_line(node, loc), _message(err), file=filename))

    if known_secrets is not None:
        issues += _secret_issues(data, node, filename, set(known_secrets))
    if cfg is not None and known_ids and cfg.connector in known_ids:
        issues.append(ValidationIssue("connector", find_line(node, ("connector",)),
                                      f"Connector id `{cfg.connector}` is defined in two files.", file=filename))
    if cfg is not None and cfg.probe is None:
        issues.append(ValidationIssue("probe", 1, "No probe is defined, so this connection is not checked "
                                      "between runs. Add a `probe` block.", "warning", filename))
    issues.sort(key=lambda i: (i.severity != "error", i.line))
    return cfg, issues


def _secret_issues(
    data: dict[str, Any], node: yaml.Node | None, filename: str, known: set[str]
) -> list[ValidationIssue]:
    """Every secret named in the config must exist in the vault. Only names are checked."""
    auth = data.get("auth")
    if not isinstance(auth, dict):
        return []
    out: list[ValidationIssue] = []
    for key in ("secret", "username_env"):
        name = auth.get(key)
        if isinstance(name, str) and ENV_NAME_RE.match(name) and name not in known:
            out.append(ValidationIssue(
                f"auth.{key}", find_line(node, ("auth", key)),
                f"Secret `{name}` is not stored. Run `secintegrate secret set {name}`.", file=filename))
    return out


def validate_paths(paths: list[Path], known_secrets: Collection[str] | None = None) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    seen: dict[str, Path] = {}
    for p in paths:
        cfg, found = validate_text(p.read_text(encoding="utf-8"), str(p), set(seen), known_secrets)
        issues += found
        if cfg is not None and cfg.connector not in seen:
            seen[cfg.connector] = p
    return issues


def validate_dir(directory: str | Path, known_secrets: Collection[str] | None = None) -> list[ValidationIssue]:
    return validate_paths(config_files(directory), known_secrets)


def existing_ids(directory: str | Path) -> set[str]:
    ids: set[str] = set()
    for f in config_files(directory):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and isinstance(data.get("connector"), str):
            ids.add(data["connector"])
    return ids
