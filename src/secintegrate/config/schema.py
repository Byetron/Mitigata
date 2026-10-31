"""Pydantic models for the connector YAML format (spec section 3, brief section 3.2)."""
from __future__ import annotations

import difflib
import ipaddress
import re
from typing import Any, Literal
from urllib.parse import urlparse

from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from ..transforms import TRANSFORMS

ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_KEY_PREFIXES = ("ghp_", "gho_", "ghs_", "github_pat_", "sk-", "xoxb-", "xoxp-", "AKIA", "AIza")
_MIN_KEY_LENGTH = 20

AUTH_TYPES = ("bearer", "basic", "api_key_header", "none")
PAGINATION_TYPES = ("link_header", "offset", "page_number", "cursor")
TARGET_FIELDS: dict[str, list[str]] = {
    "user": ["id", "name", "email", "status", "last_login"],
    "device": ["id", "hostname", "ip", "os", "owner", "last_seen"],
    "event": ["id", "type", "severity", "timestamp", "description"],
}
TARGET_REQUIRED: dict[str, list[str]] = {
    "user": ["id", "name"],
    "device": ["id"],
    "event": ["id", "timestamp", "severity"],
}
_REQUIRED_MESSAGE = {
    "user": "A user record needs `id` and `name`.",
    "device": "A device record needs `id`.",
    "event": "An event record needs `id`, `timestamp`, and `severity`.",
}


def is_internal_host(host: str) -> bool:
    """True for localhost, private and link-local addresses (including cloud metadata addresses)."""
    name = host.strip("[]").lower()
    if name == "localhost" or name.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False  # an ordinary host name; Hermes cannot know what it resolves to
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


def looks_like_real_key(value: str) -> bool:
    """Heuristic from brief 3.2: a known key prefix, a UUID, or a long mixed-case string with digits."""
    if value.startswith(_KEY_PREFIXES) or _UUID_RE.match(value):
        return True
    return (
        len(value) > _MIN_KEY_LENGTH
        and any(c.islower() for c in value)
        and any(c.isupper() for c in value)
        and any(c.isdigit() for c in value)
    )


def _one_of(label: str, options: tuple[str, ...], value: Any) -> Any:
    if value not in options:
        raise ValueError(f"Pick one of: {', '.join(options)}." if label else "")
    return value


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Auth(_Model):
    type: Literal["bearer", "basic", "api_key_header", "none"]
    secret: str | None = None
    username_env: str | None = None
    header: str | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _type(cls, v: Any) -> Any:
        return _one_of("auth", AUTH_TYPES, v)

    @field_validator("secret", "username_env")
    @classmethod
    def _env_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if looks_like_real_key(v):
            raise ValueError("This looks like a real key. Store it with `secintegrate secret set`, "
                             "then enter its name here.")
        if not ENV_NAME_RE.match(v):
            raise ValueError("Enter the environment variable name, not the key. Example: GITHUB_TOKEN.")
        return v

    @field_validator("header")
    @classmethod
    def _header(cls, v: str | None) -> str | None:
        if v is not None and not HEADER_RE.match(v):
            raise ValueError("Header name is not valid. Example: X-Api-Key.")
        return v

    @model_validator(mode="after")
    def _required(self) -> Auth:
        need = {
            "none": [],
            "bearer": ["secret"],
            "basic": ["username_env", "secret"],
            "api_key_header": ["header", "secret"],
        }[self.type]
        missing = [n for n in need if not getattr(self, n)]
        if missing:
            raise ValueError(f"Auth type `{self.type}` needs {' and '.join(missing)}.")
        return self


class RateLimit(_Model):
    max_requests: int = Field(gt=0)
    per_seconds: float = Field(gt=0)


class Retry(_Model):
    max_retries: int = Field(default=3, ge=0)
    backoff_seconds: list[float] = Field(default_factory=lambda: [1.0, 2.0, 4.0], min_length=1)
    retry_after_default: float = Field(default=30.0, ge=0)


class Probe(_Model):
    """A canary request that checks a connection without pulling data (brief 2.2)."""

    method: Literal["GET", "POST"] = "GET"
    path: str
    params: dict[str, Any] = Field(default_factory=dict)
    interval_minutes: int = Field(default=15, ge=1, le=1440)
    expect_status: int = Field(default=200, ge=100, le=599)

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("Path must start with /.")
        return v


class Pagination(_Model):
    type: Literal["link_header", "offset", "page_number", "cursor"]
    rel: str = "next"
    start_param: str | None = None
    limit_param: str | None = None
    limit: int | None = Field(default=None, gt=0)
    total_path: str | None = None
    param: str | None = None
    start: int = 1
    stop_when_empty: bool = True
    next_path: str | None = None
    max_pages: int = Field(default=1000, ge=1, le=100_000)  # a safety stop, not a target

    @field_validator("type", mode="before")
    @classmethod
    def _type(cls, v: Any) -> Any:
        return _one_of("pagination", PAGINATION_TYPES, v)

    @model_validator(mode="after")
    def _by_type(self) -> Pagination:
        if self.type == "offset" and not (self.start_param and self.limit_param):
            raise ValueError("Offset paging needs a start parameter and a limit parameter.")
        if self.type == "link_header" and self.start_param:
            raise ValueError("Link-header paging follows URLs from the server. Remove `start_param`.")
        if self.type == "page_number" and not self.param:
            raise ValueError("Page-number paging needs a page parameter.")
        if self.type == "cursor" and not (self.param and self.next_path):
            raise ValueError("Cursor paging needs a parameter name and a next-token path.")
        return self


class Incremental(_Model):
    cursor_field: str
    initial: str
    param: str | None = None
    format: str = "{value}"
    start_param: str | None = None
    end_param: str | None = None
    window_days: int = Field(default=120, gt=0)
    cursor_format: str | None = None
    lookback_minutes: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _modes(self) -> Incremental:
        windowed = bool(self.start_param or self.end_param)
        if self.param and windowed:
            raise ValueError("Choose one incremental method.")
        if not self.param and not (self.start_param and self.end_param):
            raise ValueError("Choose one incremental method: `param`, or both `start_param` and `end_param`.")
        if self.param and "{value}" not in self.format:
            raise ValueError("Incremental `format` must contain {value}.")
        return self


class FieldRule(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: str | None = Field(default=None, alias="from")
    const: Any = None
    default: Any = None
    required: bool = False
    transform: str | None = None

    @field_validator("transform")
    @classmethod
    def _known(cls, v: str | None) -> str | None:
        if v is not None and v not in TRANSFORMS:
            hint = difflib.get_close_matches(v, TRANSFORMS, n=1)
            more = f" Did you mean `{hint[0]}`?" if hint else ""
            raise ValueError(f"Unknown transform `{v}`.{more}")
        return v


class Mapping(_Model):
    target: str
    fields: dict[str, FieldRule]

    @field_validator("target", mode="before")
    @classmethod
    def _target(cls, v: Any) -> Any:
        if v not in TARGET_FIELDS:
            raise ValueError("Target must be user, device, or event.")
        return v

    @model_validator(mode="after")
    def _fields(self) -> Mapping:
        allowed = TARGET_FIELDS[self.target]
        for name, rule in self.fields.items():
            if name not in allowed:
                raise ValueError(f"`{name}` is not a field of target {self.target}. Allowed: {', '.join(allowed)}.")
            if rule.required and "default" in rule.model_fields_set:
                raise ValueError(f"Field `{name}` is marked required but also has a default. Remove one.")
        if any(n not in self.fields for n in TARGET_REQUIRED[self.target]):
            raise ValueError(_REQUIRED_MESSAGE[self.target])
        return self


class Endpoint(_Model):
    name: str
    method: Literal["GET", "POST"] = "GET"
    path: str
    vars: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    records_path: str = ""
    pagination: Pagination | None = None
    incremental: Incremental | None = None
    mapping: Mapping

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("Path must start with /.")
        return v

    @model_validator(mode="after")
    def _placeholders(self) -> Endpoint:
        for name in re.findall(r"\{(\w+)\}", self.path):
            if name not in self.vars:
                raise ValueError(f"Path placeholder {{{name}}} has no value in `vars`.")
        return self


class ConnectorConfig(_Model):
    connector: str
    source: str = Field(min_length=1)
    enabled: bool = True
    schedule: str
    base_url: str
    auth: Auth
    headers: dict[str, str] = Field(default_factory=dict)
    rate_limit: RateLimit | None = None
    retry: Retry | None = None
    probe: Probe | None = None
    endpoints: list[Endpoint] = Field(min_length=1)

    @field_validator("connector")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ID_RE.match(v):
            raise ValueError("Use 2 to 41 lowercase letters, digits, or underscores, starting with a letter.")
        return v

    @field_validator("schedule")
    @classmethod
    def _cron(cls, v: str) -> str:
        if len(v.split()) != 5:  # noqa: PLR2004
            raise ValueError("Schedule needs 5 fields, for example `*/15 * * * *`.")
        try:
            CronTrigger.from_crontab(v)
        except ValueError as exc:
            raise ValueError(f"Schedule is not a valid cron expression: {exc}") from None
        return v

    @field_validator("base_url")
    @classmethod
    def _base(cls, v: str, info: ValidationInfo) -> str:
        # Loopback http is allowed so tests can use a local mock server.
        if not v.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ValueError("Base URL must start with https://.")
        allow_internal = (info.context or {}).get("allow_internal", True)
        if not allow_internal and is_internal_host(urlparse(v).hostname or ""):
            raise ValueError("Base URL must be a public address, not this computer or a private network.")
        return v

    @model_validator(mode="after")
    def _unique_endpoints(self) -> ConnectorConfig:
        names = [e.name for e in self.endpoints]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"Endpoint names must be unique. Duplicated: {', '.join(dupes)}.")
        return self
