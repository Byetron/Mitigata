"""Diagnose a connector: a static look at its config and keys, then a live look at the API.

The aim is a plain answer to "what went wrong while getting requests?" for the user and for the security team:
what was checked, what was found, the most likely single cause, and what to do. Evidence is limited to names,
counts, status codes and timings. A diagnosis never contains a secret value or a response body.
"""
from __future__ import annotations

import difflib
import ipaddress
import json
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from .classify import FailureCategory
from .config.schema import ConnectorConfig, Endpoint, is_internal_host
from .http.client import ApiClient
from .http.retry import FetchError, RetryPolicy
from .http.trace import RequestRecord
from .incremental import plan_requests
from .mapping import get_path
from .pagination import extract_records, origin
from .secrets import redact
from .security.errors import SecIntegrateError, SecretNotFoundError
from .security.ports import SecretLoader
from .security.secret import Secret
from .storage.db import Database, now_iso

SAMPLE_RECORDS = 50
SLOW_MS = 5000
CERT_WARN_DAYS = 14
LEVELS = ("ok", "info", "warn", "error")

# The single most likely cause is the first of these that was found as a warning or error.
ROOT_CAUSE_ORDER = (
    "secret_missing", "secret_dirty", "dns_fail", "tls_fail", "network_unreachable", "auth_rejected",
    "endpoint_not_found", "records_path_missing", "records_not_list", "field_missing", "endpoint_server_error",
    "endpoint_rejected_request", "reply_not_json", "endpoint_rate_limited", "paging_cross_host", "tls_expiring",
    "dns_private", "connector_paused", "field_partial", "quarantine_backlog", "endpoint_slow", "never_succeeded",
)


@dataclass(frozen=True)
class Finding:
    code: str
    level: str  # ok, info, warn or error
    area: str  # config, secret, network, auth, endpoint, data, paging or state
    title: str
    detail: str
    fix: str = ""
    evidence: dict[str, str] = field(default_factory=dict)


@dataclass
class Diagnosis:
    connector: str
    at: str
    verdict: str  # healthy, degraded or broken
    summary: str
    root_cause: Finding | None
    findings: list[Finding]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> Diagnosis:
        raw = json.loads(text)
        cause = Finding(**raw["root_cause"]) if raw.get("root_cause") else None
        return cls(raw["connector"], raw["at"], raw["verdict"], raw["summary"], cause,
                   [Finding(**f) for f in raw["findings"]])


# --- keys: hygiene and a stand-in that hands back a cleaned value ---
def secret_issues(value: str, auth_type: str, role: str) -> list[tuple[str, str]]:
    """What is wrong with a stored key, described without repeating any of it. (code, plain description)."""
    issues: list[tuple[str, str]] = []
    if not value.strip():
        return [("empty", "the stored value is empty")]
    if value != value.strip():
        invisible = sorted({f"U+{ord(ch):04X}" for ch in value[:1] + value[-1:] if ch.isspace()})
        where = "the start" if value[0].isspace() else "the end"
        issues.append(("whitespace", f"there is an invisible space character at {where} ({', '.join(invisible)})"))
    if any(ch in value for ch in "\r\n\t"):
        issues.append(("newline", "the value contains a line break or tab"))
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'":  # noqa: PLR2004
        issues.append(("quotes", "the value is wrapped in quotation marks"))
    if role == "secret" and auth_type == "bearer" and stripped.lower().startswith("bearer "):
        issues.append(("prefix", "the value starts with the word \"Bearer\", which Hermes adds itself"))
    odd = [i for i, ch in enumerate(stripped) if not ch.isascii() and not ch.isspace()]
    if odd:
        issues.append(("non_ascii", f"there are non-ASCII characters at position(s) {', '.join(map(str, odd[:5]))}"))
    return issues


def clean_secret_value(value: str, auth_type: str, role: str) -> str:
    """The value with the common copy-and-paste damage removed. Never changes anything inside the key itself."""
    cleaned = value.replace("\r", "").replace("\n", "").replace("\t", "").strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in "\"'":  # noqa: PLR2004
        cleaned = cleaned[1:-1].strip()
    if role == "secret" and auth_type == "bearer" and cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    return cleaned


class CleanedVault:
    """Hands out secrets like the vault does, except that those listed come back cleaned. Stores nothing."""

    def __init__(self, vault: SecretLoader, cleaned: dict[str, str]) -> None:
        self._vault = vault
        self._cleaned = cleaned

    def load(self, name: str) -> Secret:
        return Secret(self._cleaned[name]) if name in self._cleaned else self._vault.load(name)


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


def inspect_secrets(cfg: ConnectorConfig, vault: SecretLoader) -> tuple[list[Finding], dict[str, str]]:
    """Check every key the connector uses. Returns findings and the cleaned value of each key that needs cleaning."""
    findings: list[Finding] = []
    cleaned: dict[str, str] = {}
    roles = [(cfg.auth.username_env, "username"), (cfg.auth.secret, "secret")]
    for name, role in roles:
        if not name:
            continue
        try:
            value = vault.load(name).reveal()
        except SecretNotFoundError:
            findings.append(Finding("secret_missing", "error", "secret", f"The key {name} is not stored",
                                    "The connector needs a key that Hermes does not have.",
                                    f"Store it with `hermes secret set {name}`.", {"name": name}))
            continue
        except SecIntegrateError as exc:
            findings.append(Finding("secret_unreadable", "error", "secret", f"The key {name} cannot be read",
                                    str(exc), "Check the master key (`hermes init`).", {"name": name}))
            continue
        issues = secret_issues(value, cfg.auth.type, role)
        if issues:
            fixed = clean_secret_value(value, cfg.auth.type, role)
            if fixed and fixed != value:
                cleaned[name] = fixed
            findings.append(Finding(
                "secret_dirty", "error", "secret", f"The stored key {name} was saved with extra characters",
                _sentence("; ".join(text for _, text in issues)) + ". This usually happens when a key is copied.",
                f"Re-enter it with `hermes secret set {name}`, or let auto-repair clean it.",
                {"name": name, "length": str(len(value)), "problems": ",".join(code for code, _ in issues)}))
        else:
            findings.append(Finding("secret_ok", "ok", "secret", f"The stored key {name} looks clean",
                                    f"{len(value)} characters, no hidden or stray characters.",
                                    evidence={"name": name}))
    return findings, cleaned


# --- network: DNS and TLS ---
Resolver = Callable[[str], list[str]]


@dataclass(frozen=True)
class TlsInfo:
    ok: bool
    days_left: int | None
    error: str | None


TlsCheck = Callable[[str, int], TlsInfo]


def default_resolver(host: str) -> list[str]:
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})


def default_tls_check(host: str, port: int) -> TlsInfo:
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection((host, port), timeout=8)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
        expires = ssl.cert_time_to_seconds(str(cert["notAfter"])) if "notAfter" in cert else None
        days = int((expires - time.time()) // 86400) if expires else None
        return TlsInfo(True, days, None)
    except ssl.SSLCertVerificationError as exc:
        return TlsInfo(False, None, f"the certificate is not trusted ({exc.verify_message})")
    except (OSError, ssl.SSLError) as exc:
        return TlsInfo(False, None, f"could not complete a secure connection ({type(exc).__name__})")


def network_findings(cfg: ConnectorConfig, resolver: Resolver, tls_check: TlsCheck) -> list[Finding]:
    url = urlparse(cfg.base_url)
    host = url.hostname or ""
    out: list[Finding] = []
    try:
        addresses = resolver(host)
    except OSError:
        return [Finding("dns_fail", "error", "network", f"The name {host} does not resolve",
                        "The computer could not find this server's address.",
                        "Check the spelling of base_url and your internet or DNS connection.", {"host": host})]
    private = [a for a in addresses if _is_private(a)]
    if private:
        out.append(Finding("dns_private", "warn", "network", f"{host} points at a private address",
                           "The name resolves to an address on this computer or a private network.",
                           "Make sure that is intended; a public API should not resolve to a private address.",
                           {"host": host, "addresses": ", ".join(private[:3])}))
    else:
        out.append(Finding("dns_ok", "ok", "network", f"{host} resolves", f"{len(addresses)} public address(es).",
                           evidence={"host": host}))
    if url.scheme == "https":
        info = tls_check(host, url.port or 443)
        if not info.ok:
            out.append(Finding("tls_fail", "error", "network", "The secure connection failed", info.error or "",
                               "Check base_url, the system clock, and any proxy or antivirus that inspects traffic.",
                               {"host": host}))
        elif info.days_left is not None and info.days_left < CERT_WARN_DAYS:
            out.append(Finding("tls_expiring", "warn", "network", "The server's certificate expires soon",
                               f"{max(info.days_left, 0)} day(s) left.", "Tell the API's owner.",
                               {"days_left": str(info.days_left)}))
        else:
            out.append(Finding("tls_ok", "ok", "network", "The secure connection works",
                               f"Certificate valid for {info.days_left} more day(s)." if info.days_left is not None
                               else "Certificate accepted.", evidence={"host": host}))
    return out


def _is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


# --- live requests ---
def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def suggest_keys(sample: list[Any], path: str) -> list[str]:
    """Names in the reply that look like the missing field (the same word in another case or style, or close)."""
    parts = path.rsplit(".", 1)
    parent_path, last = (parts[0], parts[1]) if len(parts) == 2 else ("", parts[0])  # noqa: PLR2004
    last = re.sub(r"\[\d+\]$", "", last)
    for record in sample:
        found, parent = (True, record) if not parent_path else get_path(record, parent_path)
        if found and isinstance(parent, dict):
            keys = [str(k) for k in parent]
            exact = [k for k in keys if _norm(k) == _norm(last) and k != last]
            close = difflib.get_close_matches(_norm(last), [_norm(k) for k in keys], n=3, cutoff=0.75)
            near = [k for k in keys if _norm(k) in close and k != last]
            return (exact + [k for k in near if k not in exact])[:3]
    return []


def _first_request(cfg: ConnectorConfig, ep: Endpoint, db: Database) -> tuple[str, dict[str, Any]]:
    """The request the runner would send first, so the diagnosis sees what a run sees."""
    url = cfg.base_url.rstrip("/") + ep.path.format(**{k: str(v) for k, v in ep.vars.items()})
    params: dict[str, Any] = dict(ep.params)
    pag = ep.pagination
    if pag is not None and pag.type == "offset":
        params[pag.start_param or ""] = 0
        if pag.limit is not None:
            params[pag.limit_param or ""] = pag.limit
    elif pag is not None and pag.type == "page_number":
        params[pag.param or ""] = pag.start
    if ep.incremental:
        params.update(plan_requests(ep.incremental, db.get_cursor(cfg.connector, ep.name))[0])
    return url, params


def _failure_finding(  # noqa: PLR0911
    exc: Exception, record: RequestRecord | None, what: str, path: str) -> Finding:
    category = exc.category if isinstance(exc, FetchError) else FailureCategory.UNKNOWN
    evidence = {"request": f"{record.method} {record.path}" if record else path,
                "status": str(record.status) if record and record.status else "no reply"}
    detail_status = f"HTTP {record.status}" if record and record.status else "no reply"
    if category is FailureCategory.AUTH_FAILED:
        return Finding("auth_rejected", "error", "auth", f"The API rejected the login ({what})",
                       f"{detail_status}: the key was sent and refused.",
                       "Create a new key at the provider and store it with `hermes secret set NAME`. "
                       "Check the key has the access this endpoint needs.", evidence)
    if category is FailureCategory.NOT_FOUND:
        return Finding("endpoint_not_found", "error", "endpoint", f"The address was not found ({what})",
                       "HTTP 404: the server does not know this path.",
                       f"Check base_url and path in the config. The path used was {path}.", evidence)
    if category is FailureCategory.RATE_LIMITED:
        wait = f" It asked to wait {record.retry_after}s." if record and record.retry_after else ""
        return Finding("endpoint_rate_limited", "warn", "endpoint", f"The API is limiting requests ({what})",
                       f"HTTP 429.{wait}", "Lower the schedule frequency or add a rate_limit to the config.", evidence)
    if category is FailureCategory.SERVER_ERROR:
        return Finding("endpoint_server_error", "error", "endpoint", f"The provider is failing ({what})",
                       f"{detail_status}: the server reported an error.",
                       "Wait and retry; check the provider's status page.", evidence)
    if category is FailureCategory.NETWORK:
        return Finding("network_unreachable", "error", "network", f"The API could not be reached ({what})",
                       f"No reply arrived ({record.error if record and record.error else 'connection failed'}).",
                       "Check the internet connection, a proxy or firewall, and the base_url.", evidence)
    if category is FailureCategory.CLIENT_ERROR:
        return Finding("endpoint_rejected_request", "error", "endpoint", f"The API rejected the request ({what})",
                       f"{detail_status}: the request was refused as invalid.",
                       "Review params and path in the config against the API's documentation.", evidence)
    if "malformed JSON" in str(exc):
        return Finding("reply_not_json", "error", "data", f"The reply is not valid JSON ({what})",
                       "The server answered, but the body could not be read as JSON "
                       f"({record.content_type if record and record.content_type else 'unknown type'}).",
                       "The address may return a web page (a login or error page). Check base_url and path.", evidence)
    return Finding("endpoint_unexpected", "error", "endpoint", f"Something unexpected went wrong ({what})",
                   type(exc).__name__, "See the log for details.", evidence)


def live_findings(cfg: ConnectorConfig, db: Database, vault: SecretLoader, transport: httpx.BaseTransport | None,
                  sleep: Callable[[float], None]) -> list[Finding]:
    out: list[Finding] = []
    captured: list[RequestRecord] = []

    def record(rec: RequestRecord) -> None:
        captured.append(rec)
        db.add_request(cfg.connector, rec)

    client = ApiClient(cfg, vault, throttle=False, sleep=sleep, transport=transport, recorder=record, kind="diagnose")
    client.policy = RetryPolicy(max_retries=0, max_rate_limit_waits=0)  # one honest attempt, not a retry loop
    try:
        if cfg.probe is not None:
            before = len(captured)
            try:
                reply = client.probe(cfg.probe, cfg.base_url)
                out += [_ok_or_slow("probe", reply.status, captured[before:], cfg.probe.path)]
            except (FetchError, SecIntegrateError, httpx.HTTPError, ValueError) as exc:
                out.append(_failure_finding(exc, captured[-1] if len(captured) > before else None, "health check",
                                            cfg.probe.path))
        ep = cfg.endpoints[0]
        url, params = _first_request(cfg, ep, db)
        before = len(captured)
        try:
            page = client.request(ep.method, url, params)
        except (FetchError, SecIntegrateError, httpx.HTTPError, ValueError) as exc:
            out.append(_failure_finding(exc, captured[-1] if len(captured) > before else None, "data request", ep.path))
            return out
        out.append(_ok_or_slow("data", captured[-1].status or 0, captured[before:], ep.path))
        out += _reply_findings(cfg, ep, page.data, page.headers, url)
    finally:
        client.close()
    return out


def _ok_or_slow(what: str, status: int, records: list[RequestRecord], path: str) -> Finding:
    latency = records[-1].latency_ms if records else 0
    if latency > SLOW_MS:
        return Finding("endpoint_slow", "warn", "endpoint", f"The API answered slowly ({what})",
                       f"HTTP {status} after {latency / 1000:.1f}s.",
                       "A slow API may time out; consider a longer interval.",
                       {"request": path, "latency_ms": str(latency)})
    return Finding("endpoint_ok", "ok", "endpoint", f"The API answered ({what})", f"HTTP {status} in {latency} ms.",
                   evidence={"request": path, "latency_ms": str(latency)})


def _reply_findings(cfg: ConnectorConfig, ep: Endpoint, data: Any, headers: httpx.Headers, url: str) -> list[Finding]:
    out: list[Finding] = []
    if data is None:
        return [Finding("reply_empty", "info", "data", "The reply had no body",
                        "Hermes treats an empty reply as \"nothing new\".")]
    try:
        records = extract_records(data, ep.records_path)
    except FetchError as exc:
        keys = ", ".join(sorted(str(k) for k in data)[:12]) if isinstance(data, dict) else type(data).__name__
        if ep.records_path and isinstance(data, dict):
            close = difflib.get_close_matches(ep.records_path, [str(k) for k in data], n=2, cutoff=0.5)
            hint = f" Did you mean `{close[0]}`?" if close else ""
            return [Finding("records_path_missing", "error", "data", "The list of records is not where the config says",
                            f"records_path `{ep.records_path}` is not in the reply.{hint}",
                            "Set records_path to the name that holds the list.", {"top_level_keys": keys})]
        return [Finding("records_not_list", "error", "data", "The reply is not a list of records", exc.detail,
                        "Set records_path to where the list is, or check the endpoint.", {"top_level_keys": keys})]
    if not records:
        out.append(Finding("records_empty", "info", "data", "The reply contained no records",
                           "Nothing new right now, so the field mapping could not be checked against real data."))
    else:
        out += _mapping_findings(ep, [r for r in records[:SAMPLE_RECORDS] if isinstance(r, dict)], len(records))
    out += _paging_findings(ep, data, headers, url)
    return out


def _mapping_findings(ep: Endpoint, sample: list[dict[str, Any]], total: int) -> list[Finding]:
    out: list[Finding] = []
    if not sample:
        return [Finding("records_not_objects", "warn", "data", "The records are not objects",
                        "Each record should be a JSON object with named fields.")]
    bad = 0
    for name, rule in ep.mapping.fields.items():
        if rule.from_ is None:
            continue
        have = sum(1 for rec in sample if get_path(rec, rule.from_)[0] and get_path(rec, rule.from_)[1] is not None)
        if have == len(sample):
            continue
        bad += 1
        near = suggest_keys(sample, rule.from_)
        hint = f" The reply has: {', '.join(f'`{k}`' for k in near)}." if near else ""
        evidence = {"field": name, "source_path": rule.from_, "present_in": f"{have} of {len(sample)} records"}
        if have == 0:
            out.append(Finding("field_missing", "error" if rule.required else "warn", "data",
                               f"The field `{rule.from_}` is not in the reply",
                               f"Not found in any of {len(sample)} sampled records.{hint}",
                               f"Change `from: {rule.from_}` in the mapping" + (f" to `{near[0]}`." if near else "."),
                               evidence | ({"suggestion": near[0]} if near else {})))
        else:
            out.append(Finding("field_partial", "warn", "data", f"The field `{rule.from_}` is sometimes missing",
                               f"Present in {have} of {len(sample)} records. Records without it are set aside "
                               "if it is required, or get the default.",
                               "Add a default, or accept the quarantined records.",
                               evidence))
    if not bad:
        out.append(Finding("fields_ok", "ok", "data", "The records match the mapping",
                           f"Every mapped field was found in all {len(sample)} sampled records (of {total}).",
                           evidence={"sampled": str(len(sample))}))
    return out


def _paging_findings(ep: Endpoint, data: Any, headers: httpx.Headers, url: str) -> list[Finding]:
    pag = ep.pagination
    if pag is None:
        return []
    if pag.type == "link_header":
        from .pagination import parse_link_header  # noqa: PLC0415 - only needed here

        nxt = parse_link_header(headers.get("link"), pag.rel)
        if nxt is None:
            return [Finding("paging_single_page", "info", "paging", "No next-page link in the reply",
                            "Either this is the last page or the API does not send a Link header.")]
        if origin(httpx.URL(url).join(nxt).__str__()) != origin(url):
            return [Finding("paging_cross_host", "error", "paging", "The next-page link points to another server",
                            "Hermes will not follow it, because it would send the key there.",
                            "Report this to the API's owner; it may be misconfigured or tampered with.")]
        return [Finding("paging_ok", "ok", "paging", "The next-page link is on the same server", "")]
    if pag.type == "offset" and pag.total_path and not get_path(data, pag.total_path)[0]:
        return [Finding("paging_total_missing", "warn", "paging", "The total count is not in the reply",
                        f"total_path `{pag.total_path}` was not found, so paging ends only on an empty page.",
                        "Set total_path to where the count is, or remove it.")]
    return []


# --- state held in the database ---
def state_findings(cfg: ConnectorConfig, db: Database) -> list[Finding]:
    out: list[Finding] = []
    conn = db.get_connection(cfg.connector) or {}
    if conn.get("paused"):
        out.append(Finding("connector_paused", "warn", "state", "The connector is paused",
                           "It was paused after repeated login failures, so it makes no requests.",
                           "Fix the key, then it resumes by itself (or run `hermes resume`).",
                           {"failures_in_a_row": str(conn.get("consecutive_failures") or 0)}))
    backlog = db.count_rows("quarantine", cfg.connector)
    if backlog:
        out.append(Finding("quarantine_backlog", "warn", "state", f"{backlog} record(s) were set aside as invalid",
                           "They did not match the mapping. They are re-tried after each good run.",
                           "Check the field mapping if this number keeps growing.", {"records": str(backlog)}))
    if db.last_success(cfg.connector) is None and conn.get("last_run_finished_at"):
        out.append(Finding("never_succeeded", "info", "state", "No run has ever succeeded",
                           "This connector has run, but never completed successfully."))
    if cfg.probe is None:
        out.append(Finding("config_no_probe", "info", "config", "No health check is configured",
                           "Without a probe, problems show up only when a run fails.", "Add a `probe` block."))
    return out


# --- putting it together ---
def summarise(connector: str, findings: list[Finding]) -> Diagnosis:
    problems = [f for f in findings if f.level in ("warn", "error")]
    root = next((f for code in ROOT_CAUSE_ORDER for f in problems if f.code == code), problems[0] if problems else None)
    if any(f.level == "error" for f in findings):
        verdict = "broken"
    elif problems:
        verdict = "degraded"
    else:
        verdict = "healthy"
    if root is None:
        summary = "Everything checked is working: the key is clean, the API answers, and the data matches the mapping."
    else:
        summary = f"{root.title}. {root.fix}".strip()
    safe = [Finding(f.code, f.level, f.area, redact(f.title), redact(f.detail), redact(f.fix),
                    {k: redact(v) for k, v in f.evidence.items()}) for f in findings]
    return Diagnosis(connector, now_iso(), verdict, redact(summary),
                     next((f for f in safe if root and f.code == root.code), None), safe)


def diagnose(cfg: ConnectorConfig, db: Database, vault: SecretLoader, *, resolver: Resolver = default_resolver,
             tls_check: TlsCheck = default_tls_check, transport: httpx.BaseTransport | None = None,
             sleep: Callable[[float], None] = time.sleep, save: bool = True, live: bool = True) -> Diagnosis:
    """Run every check. A failing step never stops the others: it becomes a finding."""
    findings, cleaned = inspect_secrets(cfg, vault)
    findings += network_findings(cfg, resolver, tls_check) if live else []
    unreachable = any(f.code in ("dns_fail", "tls_fail") for f in findings)
    blocked = any(f.code in ("secret_missing", "secret_unreadable") for f in findings)
    if live and not unreachable and not blocked:
        usable: SecretLoader = CleanedVault(vault, cleaned) if cleaned else vault
        findings += live_findings(cfg, db, usable, transport, sleep)
        if cleaned and not any(f.code in ("auth_rejected", "network_unreachable") for f in findings):
            findings.append(Finding("secret_clean_accepted", "info", "secret",
                                    "With the extra characters removed, the API accepts the key",
                                    "The checks above were run with the cleaned key.",
                                    evidence={"names": ", ".join(cleaned)}))
    elif live and (unreachable or blocked):
        findings.append(Finding("live_skipped", "info", "config", "The live checks were skipped",
                                "Fix the problem above first; the API cannot be tested until then."))
    findings += state_findings(cfg, db)
    diagnosis = summarise(cfg.connector, findings)
    if save:
        db.save_diagnosis(cfg.connector, diagnosis.verdict, diagnosis.to_json())
    return diagnosis


__all__ = ["CleanedVault", "Diagnosis", "Finding", "clean_secret_value", "diagnose", "is_internal_host",
           "secret_issues", "suggest_keys"]
_ = (datetime, UTC)  # kept importable for callers that format the report's timestamp
