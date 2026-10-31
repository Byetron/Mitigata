"""Pydantic models for the connector YAML format (spec section 3)."""
from __future__ import annotations

import difflib
import re
from typing import Any, Literal

from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..transforms import TRANSFORMS

ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ID_RE = re.compile(r"^[a-z0-9_]+$")
HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

TARGET_FIELDS = {
    "user": ["id", "name", "email", "status", "last_login"],
    "device": ["id", "hostname", "ip", "os", "owner", "last_seen"],
    "event": ["id", "type", "severity", "timestamp", "description"],
}
TARGET_REQUIRED = {"user": ["id", "name"], "device": ["id"], "event": ["id", "type"]}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Auth(_Model):
    type: Literal["bearer", "basic", "api_key_header", "none"]
    secret: str | None = None
    username_env: str | None = None
    header: str | None = None

    @field_validator("secret", "username_env")
    @classmethod
    def _env_name(cls, v):
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError("looks like a real value. Use an env var name such as GITHUB_TOKEN")
        return v

    @field_validator("header")
    @classmethod
    def _header(cls, v):
        if v is not None and not HEADER_RE.match(v):
            raise ValueError("is not a valid HTTP header name")
        return v

    @model_validator(mode="after")
    def _required(self):
        need = {
            "none": [],
            "bearer": ["secret"],
            "basic": ["username_env", "secret"],
            "api_key_header": ["header", "secret"],
        }[self.type]
        missing = [n for n in need if not getattr(self, n)]
        if missing:
            raise ValueError(f"auth type={self.type} requires {' and '.join(missing)}")
        return self


class RateLimit(_Model):
    max_requests: int = Field(gt=0)
    per_seconds: float = Field(gt=0)


class Retry(_Model):
    max_retries: int = Field(default=3, ge=0)
    backoff_seconds: list[float] = Field(default_factory=lambda: [1.0, 2.0, 4.0], min_length=1)
    retry_after_default: float = Field(default=30.0, ge=0)


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

    @model_validator(mode="after")
    def _by_type(self):
        t = self.type
        if t == "offset" and not (self.start_param and self.limit_param):
            raise ValueError("pagination.type=offset requires start_param and limit_param")
        if t == "page_number" and not self.param:
            raise ValueError("pagination.type=page_number requires param")
        if t == "cursor" and not (self.param and self.next_path):
            raise ValueError("pagination.type=cursor requires param and next_path")
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
    def _modes(self):
        windowed = bool(self.start_param or self.end_param)
        if self.param and windowed:
            raise ValueError("incremental.param and start_param/end_param are mutually exclusive")
        if not self.param and not (self.start_param and self.end_param):
            raise ValueError("incremental requires either param, or both start_param and end_param")
        if self.param and "{value}" not in self.format:
            raise ValueError("incremental.format must contain {value}")
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
    def _known(cls, v):
        if v is not None and v not in TRANSFORMS:
            hint = difflib.get_close_matches(v, TRANSFORMS, n=1)
            more = f" Did you mean {hint[0]}?" if hint else ""
            raise ValueError(f'"{v}" is not a known transform.{more}')
        return v


class Mapping(_Model):
    target: str
    fields: dict[str, FieldRule]

    @field_validator("target")
    @classmethod
    def _target(cls, v):
        if v not in TARGET_FIELDS:
            raise ValueError("must be one of user, device, event")
        return v

    @model_validator(mode="after")
    def _fields(self):
        allowed = TARGET_FIELDS[self.target]
        for name in self.fields:
            if name not in allowed:
                raise ValueError(f"field '{name}' is not valid for target {self.target}; allowed: {', '.join(allowed)}")
        need = TARGET_REQUIRED[self.target]
        missing = [n for n in need if n not in self.fields]
        if missing:
            raise ValueError(f"mapping.target={self.target} requires {' and '.join(need)} (missing {', '.join(missing)})")
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
    def _path(cls, v):
        if not v.startswith("/"):
            raise ValueError("must start with /")
        return v

    @model_validator(mode="after")
    def _placeholders(self):
        for name in re.findall(r"\{(\w+)\}", self.path):
            if name not in self.vars:
                raise ValueError(f"path placeholder {{{name}}} has no value in vars")
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
    endpoints: list[Endpoint] = Field(min_length=1)

    @field_validator("connector")
    @classmethod
    def _id(cls, v):
        if not ID_RE.match(v):
            raise ValueError("must contain only lowercase letters, digits and underscores")
        return v

    @field_validator("schedule")
    @classmethod
    def _cron(cls, v):
        parts = v.split()
        if len(parts) != 5:
            raise ValueError(f'"{v}" has {len(parts)} fields, expected 5')
        try:
            CronTrigger.from_crontab(v)
        except ValueError as exc:
            raise ValueError(f'"{v}" is not a valid cron expression: {exc}') from None
        return v

    @field_validator("base_url")
    @classmethod
    def _base(cls, v):
        ok = v.startswith(("https://", "${", "http://localhost", "http://127.0.0.1"))
        if not ok:
            raise ValueError("must start with https:// or be a ${ENV_VAR}")
        return v

    @model_validator(mode="after")
    def _unique_endpoints(self):
        names = [e.name for e in self.endpoints]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"endpoint names must be unique, duplicated: {', '.join(dupes)}")
        return self
