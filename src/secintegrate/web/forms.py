"""B5: turn the web form into a connector config dict. No secret values are accepted."""
from __future__ import annotations

import re
from typing import Any

from ..config.schema import ENV_NAME_RE, HEADER_RE, ID_RE, TARGET_FIELDS

MAP_ROWS = 8

TEXT_FIELDS = [
    "connector_id", "source", "base_url", "auth_type", "secret_env", "username_env", "header_name",
    "endpoint_name", "path", "records_path", "pagination_type", "rel", "start_param", "limit_param",
    "limit", "total_path", "page_param", "page_start", "schedule", "mapping_target",
]


def parse_form(form) -> dict[str, Any]:
    values: dict[str, Any] = {k: (form.get(k) or "").strip() for k in TEXT_FIELDS}
    values["rows"] = [
        {
            "target": (form.get(f"map_target_{i}") or "").strip(),
            "source": (form.get(f"map_source_{i}") or "").strip(),
            "transform": (form.get(f"map_transform_{i}") or "").strip(),
            "required": (form.get(f"map_required_{i}") or "") == "yes",
        }
        for i in range(MAP_ROWS)
    ]
    return values


def default_values() -> dict[str, Any]:
    v: dict[str, Any] = {k: "" for k in TEXT_FIELDS}
    v.update(auth_type="bearer", pagination_type="none", mapping_target="event", endpoint_name="main",
             rel="next", schedule="0 * * * *")
    v["rows"] = [{"target": "", "source": "", "transform": "", "required": False} for _ in range(MAP_ROWS)]
    return v


def precheck(v: dict[str, Any]) -> dict[str, str]:
    """Form-level checks that give friendlier messages than the YAML validator."""
    errors: dict[str, str] = {}
    if not ID_RE.match(v["connector_id"]):
        errors["connector_id"] = "lowercase letters, digits and underscores only"
    if not v["source"]:
        errors["source"] = "required"
    if not v["base_url"].startswith("https://"):
        errors["base_url"] = "must start with https://"
    if v["auth_type"] != "none" and not ENV_NAME_RE.match(v["secret_env"]):
        errors["secret_env"] = "enter an env var NAME such as GITHUB_TOKEN, never the secret itself"
    if v["auth_type"] == "basic" and not ENV_NAME_RE.match(v["username_env"]):
        errors["username_env"] = "enter an env var name such as JIRA_EMAIL"
    if v["auth_type"] == "api_key_header" and not HEADER_RE.match(v["header_name"] or " "):
        errors["header_name"] = "enter a valid HTTP header name"
    if not v["path"].startswith("/"):
        errors["path"] = "must start with /"
    for key in ("limit", "page_start"):
        if v[key] and not re.fullmatch(r"\d+", v[key]):
            errors[key] = "must be a whole number"
    if v["pagination_type"] == "offset" and not (v["start_param"] and v["limit_param"]):
        errors["start_param"] = "offset paging needs start and limit parameter names"
    if v["pagination_type"] == "page_number" and not v["page_param"]:
        errors["page_param"] = "page_number paging needs a parameter name"
    used = [r for r in v["rows"] if r["target"] or r["source"]]
    if not used:
        errors["mapping"] = "add at least one mapping row"
    for r in used:
        if r["target"] not in TARGET_FIELDS.get(v["mapping_target"], []):
            errors["mapping"] = f"'{r['target']}' is not a field of target {v['mapping_target']}"
    return errors


def build_config(v: dict[str, Any]) -> dict[str, Any]:
    auth: dict[str, Any] = {"type": v["auth_type"]}
    if v["auth_type"] != "none":
        auth["secret"] = v["secret_env"]
    if v["auth_type"] == "basic":
        auth["username_env"] = v["username_env"]
    if v["auth_type"] == "api_key_header":
        auth["header"] = v["header_name"]

    endpoint: dict[str, Any] = {
        "name": v["endpoint_name"] or "main",
        "method": "GET",
        "path": v["path"],
        "records_path": v["records_path"],
    }
    p = v["pagination_type"]
    if p == "link_header":
        endpoint["pagination"] = {"type": p, "rel": v["rel"] or "next"}
    elif p == "offset":
        pag: dict[str, Any] = {"type": p, "start_param": v["start_param"], "limit_param": v["limit_param"]}
        if v["limit"].isdigit():
            pag["limit"] = int(v["limit"])
        if v["total_path"]:
            pag["total_path"] = v["total_path"]
        endpoint["pagination"] = pag
    elif p == "page_number":
        endpoint["pagination"] = {"type": p, "param": v["page_param"], "start": int(v["page_start"]) if v["page_start"].isdigit() else 1}

    fields: dict[str, Any] = {}
    for r in v["rows"]:
        if not (r["target"] and r["source"]):
            continue
        rule: dict[str, Any] = {"from": r["source"]}
        if r["transform"]:
            rule["transform"] = r["transform"]
        if r["required"]:
            rule["required"] = True
        else:
            rule["default"] = None
        fields[r["target"]] = rule
    endpoint["mapping"] = {"target": v["mapping_target"], "fields": fields}

    return {
        "connector": v["connector_id"],
        "source": v["source"],
        "enabled": True,
        "schedule": v["schedule"],
        "base_url": v["base_url"],
        "auth": auth,
        "endpoints": [endpoint],
    }


_PATH_TO_FIELD = [
    ("connector", "connector_id"), ("source", "source"), ("base_url", "base_url"),
    ("schedule", "schedule"), ("auth.secret", "secret_env"), ("auth.username_env", "username_env"),
    ("auth.header", "header_name"), ("auth", "auth_type"), ("endpoints[0].path", "path"),
    ("endpoints[0].records_path", "records_path"), ("endpoints[0].pagination.limit", "limit"),
    ("endpoints[0].pagination", "pagination_type"), ("endpoints[0].mapping.target", "mapping_target"),
    ("endpoints[0].mapping", "mapping"),
]


def field_for_path(path: str) -> str | None:
    best = None
    for prefix, name in _PATH_TO_FIELD:
        if (path == prefix or path.startswith((prefix + ".", prefix + "["))) and (
            best is None or len(prefix) > len(best[0])
        ):
            best = (prefix, name)
    return best[1] if best else None
