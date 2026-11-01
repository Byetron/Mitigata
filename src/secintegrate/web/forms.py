"""B5: turn the web form into a connector config dict. No secret values are accepted.

All rules live in the shared validator; this module only builds the dict (brief 3.1).
"""
from __future__ import annotations

from collections.abc import Mapping as MappingABC
from typing import Any

from ..config.schema import ENV_NAME_RE
from ..config.validator import ValidationIssue

MAP_ROWS = 8

TEXT_FIELDS = [
    "connector_id", "source", "base_url", "auth_type", "secret_env", "username_env", "header_name",
    "endpoint_name", "path", "records_path", "pagination_type", "rel", "start_param", "limit_param",
    "limit", "total_path", "page_param", "page_start", "schedule", "mapping_target",
    "probe_path", "probe_interval",
]
SECRET_FIELDS = ("secret_env", "username_env")


def blank_row() -> dict[str, Any]:
    return {"target": "", "source": "", "transform": "", "required": False}


def parse_form(form: MappingABC[str, str]) -> dict[str, Any]:
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
    v["rows"] = [blank_row() for _ in range(MAP_ROWS)]
    return v


def safe_for_display(values: dict[str, Any]) -> dict[str, Any]:
    """Never echo something that is not a variable name back into the page (it may be a pasted key)."""
    shown = dict(values)
    for name in SECRET_FIELDS:
        if shown.get(name) and not ENV_NAME_RE.match(shown[name]):
            shown[name] = ""
    return shown


def _number(text: str) -> int | str:
    """Digits become an int; anything else is passed through so the validator reports it."""
    return int(text) if text.isdigit() else text


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
    kind = v["pagination_type"]
    if kind == "link_header":
        endpoint["pagination"] = {"type": kind, "rel": v["rel"] or "next"}
    elif kind == "offset":
        pag: dict[str, Any] = {"type": kind, "start_param": v["start_param"], "limit_param": v["limit_param"]}
        if v["limit"]:
            pag["limit"] = _number(v["limit"])
        if v["total_path"]:
            pag["total_path"] = v["total_path"]
        endpoint["pagination"] = pag
    elif kind == "page_number":
        endpoint["pagination"] = {"type": kind, "param": v["page_param"],
                                  "start": _number(v["page_start"]) if v["page_start"] else 1}

    fields: dict[str, Any] = {}
    for row in v["rows"]:
        if not (row["target"] and row["source"]):
            continue
        rule: dict[str, Any] = {}
        if row["source"].startswith("="):  # "=high" means the fixed value "high"
            rule["const"] = row["source"][1:]
        else:
            rule["from"] = row["source"]
            if row["transform"]:
                rule["transform"] = row["transform"]
            if row["required"]:
                rule["required"] = True
            else:
                rule["default"] = None
        fields[row["target"]] = rule
    endpoint["mapping"] = {"target": v["mapping_target"], "fields": fields}

    config: dict[str, Any] = {
        "connector": v["connector_id"],
        "source": v["source"],
        "enabled": True,
        "schedule": v["schedule"],
        "base_url": v["base_url"],
        "auth": auth,
        "endpoints": [endpoint],
    }
    if v["probe_path"]:
        config["probe"] = {"method": "GET", "path": v["probe_path"],
                           "interval_minutes": _number(v["probe_interval"]) if v["probe_interval"] else 15}
    return config


_PATH_TO_FIELD = [
    ("connector", "connector_id"), ("source", "source"), ("base_url", "base_url"),
    ("schedule", "schedule"), ("auth.secret", "secret_env"), ("auth.username_env", "username_env"),
    ("auth.header", "header_name"), ("auth", "auth_type"), ("endpoints[0].name", "endpoint_name"),
    ("endpoints[0].path", "path"), ("endpoints[0].records_path", "records_path"),
    ("endpoints[0].pagination.limit", "limit"), ("endpoints[0].pagination.start_param", "start_param"),
    ("endpoints[0].pagination.limit_param", "limit_param"), ("endpoints[0].pagination.param", "page_param"),
    ("endpoints[0].pagination.start", "page_start"), ("endpoints[0].pagination", "pagination_type"),
    ("endpoints[0].mapping.target", "mapping_target"), ("endpoints[0].mapping", "mapping"),
    ("probe.path", "probe_path"), ("probe.interval_minutes", "probe_interval"), ("probe", "probe_path"),
]


def field_for_path(path: str) -> str | None:
    best: tuple[str, str] | None = None
    for prefix, name in _PATH_TO_FIELD:
        if (path == prefix or path.startswith((prefix + ".", prefix + "["))) and (
            best is None or len(prefix) > len(best[0])
        ):
            best = (prefix, name)
    return best[1] if best else None


def group_issues(issues: list[ValidationIssue]) -> tuple[dict[str, list[ValidationIssue]], list[ValidationIssue]]:
    """Split issues into per-field lists and those that belong to no single field."""
    by_field: dict[str, list[ValidationIssue]] = {}
    general: list[ValidationIssue] = []
    for issue in issues:
        name = field_for_path(issue.path)
        if name:
            by_field.setdefault(name, []).append(issue)
        else:
            general.append(issue)
    return by_field, general


def _row(target: str, source: str, transform: str = "", required: bool = False) -> dict[str, Any]:
    return {"target": target, "source": source, "transform": transform, "required": required}


def _fill(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return rows + [blank_row() for _ in range(MAP_ROWS - len(rows))]


def presets() -> dict[str, dict[str, Any]]:
    """Starting points the user then edits (brief 3.4). Jira was removed from this app."""
    base = default_values()
    return {
        "github": {**base, "connector_id": "github_example", "source": "github",
                   "base_url": "https://api.github.com", "schedule": "*/15 * * * *", "auth_type": "bearer",
                   "secret_env": "GITHUB_TOKEN", "endpoint_name": "advisories", "path": "/advisories",
                   "pagination_type": "link_header", "rel": "next", "mapping_target": "event",
                   "probe_path": "/user", "probe_interval": "15",
                   "rows": _fill([_row("id", "ghsa_id", "", True), _row("type", "=advisory"),
                                  _row("severity", "severity", "lower"),
                                  _row("timestamp", "published_at", "iso8601", True),
                                  _row("description", "summary")])},
        "nvd": {**base, "connector_id": "nvd_example", "source": "nvd",
                "base_url": "https://services.nvd.nist.gov", "schedule": "0 */2 * * *",
                "auth_type": "api_key_header", "header_name": "apiKey", "secret_env": "NVD_API_KEY",
                "endpoint_name": "cves", "path": "/rest/json/cves/2.0", "records_path": "vulnerabilities",
                "pagination_type": "offset", "start_param": "startIndex", "limit_param": "resultsPerPage",
                "limit": "2000", "total_path": "totalResults", "mapping_target": "event",
                "probe_path": "/rest/json/cves/2.0?resultsPerPage=1", "probe_interval": "30",
                "rows": _fill([_row("id", "cve.id", "", True), _row("type", "=cve"),
                               _row("severity", "cve.metrics.cvssMetricV31[0].cvssData.baseSeverity", "lower"),
                               _row("timestamp", "cve.published", "iso8601", True),
                               _row("description", "cve.descriptions[0].value")])},
        "public": {**base, "connector_id": "cisa_example", "source": "cisa",
                   "base_url": "https://www.cisa.gov", "schedule": "0 */6 * * *", "auth_type": "none",
                   "endpoint_name": "kev",
                   "path": "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                   "records_path": "vulnerabilities", "pagination_type": "none", "mapping_target": "event",
                   "rows": _fill([_row("id", "cveID", "", True), _row("type", "=kev"),
                                  _row("severity", "=high"),
                                  _row("timestamp", "dateAdded", "iso8601", True),
                                  _row("description", "shortDescription")])},
    }


def public_feeds() -> list[dict[str, Any]]:
    """Keyless public feeds. The "Public feed" button loads a different one at random each click."""
    base = default_values()
    common = {"auth_type": "none", "pagination_type": "none"}
    feeds = [
        {**base, **common, "label": "CISA known exploited vulnerabilities", "connector_id": "cisa_example",
         "source": "cisa", "base_url": "https://www.cisa.gov", "schedule": "0 */6 * * *", "endpoint_name": "kev",
         "path": "/sites/default/files/feeds/known_exploited_vulnerabilities.json", "records_path": "vulnerabilities",
         "mapping_target": "event",
         "rows": _fill([_row("id", "cveID", "", True), _row("type", "=kev"), _row("severity", "=high"),
                        _row("timestamp", "dateAdded", "iso8601", True), _row("description", "shortDescription")])},
        {**base, **common, "label": "FIRST EPSS exploit-probability scores", "connector_id": "epss_example",
         "source": "first_epss", "base_url": "https://api.first.org", "schedule": "0 6 * * *",
         "endpoint_name": "epss", "path": "/data/v1/epss", "records_path": "data", "mapping_target": "event",
         "rows": _fill([_row("id", "cve", "", True), _row("type", "=epss"), _row("severity", "=info"),
                        _row("timestamp", "date", "iso8601", True), _row("description", "epss", "to_string")])},
        {**base, **common, "label": "Ransomware.live recent victims", "connector_id": "ransomware_example",
         "source": "ransomware_live", "base_url": "https://api.ransomware.live", "schedule": "0 */3 * * *",
         "endpoint_name": "victims", "path": "/v2/recentvictims", "mapping_target": "event",
         "rows": _fill([_row("id", "url", "", True), _row("type", "=ransomware"), _row("severity", "=high"),
                        _row("timestamp", "discovered", "iso8601", True), _row("description", "victim")])},
        {**base, **common, "label": "SANS ISC top attacking IPs", "connector_id": "sans_isc_example",
         "source": "sans_isc", "base_url": "https://isc.sans.edu", "schedule": "0 */4 * * *",
         "endpoint_name": "attackers", "path": "/api/sources/attacks/100?json", "mapping_target": "device",
         "rows": _fill([_row("id", "ip", "", True), _row("ip", "ip", "", True),
                        _row("last_seen", "lastseen", "iso8601")])},
        {**base, **common, "label": "Feodo Tracker botnet C2 servers", "connector_id": "feodo_example",
         "source": "feodo", "base_url": "https://feodotracker.abuse.ch", "schedule": "30 */4 * * *",
         "endpoint_name": "blocklist", "path": "/downloads/ipblocklist.json", "mapping_target": "device",
         "rows": _fill([_row("id", "ip_address", "", True), _row("ip", "ip_address", "", True),
                        _row("os", "malware"), _row("owner", "as_name"),
                        _row("last_seen", "last_online", "iso8601")])},
    ]
    return feeds
