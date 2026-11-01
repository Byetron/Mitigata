"""The diagnosis: it names what went wrong, with evidence, and never leaks a key."""
from __future__ import annotations

import json
from typing import Any

import httpx

from conftest import FAKE_TOKEN, advisory, make_cfg
from secintegrate.diagnose import (
    Diagnosis,
    TlsInfo,
    clean_secret_value,
    diagnose,
    secret_issues,
    suggest_keys,
)
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database

BASE = "https://api.example.test"


def resolver_ok(host: str) -> list[str]:
    return ["93.184.216.34"]


def tls_ok(host: str, port: int) -> TlsInfo:
    return TlsInfo(True, 90, None)


def serve(status: int = 200, body: Any = None, headers: dict[str, str] | None = None) -> httpx.MockTransport:
    payload = [advisory(1)] if body is None else body
    return httpx.MockTransport(lambda r: httpx.Response(status, json=payload, headers=headers or {}))


def run_diag(db: Database, vault: SecretVault, transport: httpx.MockTransport, **over: Any) -> Diagnosis:
    return diagnose(make_cfg(BASE, **over), db, vault, resolver=resolver_ok, tls_check=tls_ok, transport=transport,
                    sleep=lambda s: None)


def codes(d: Diagnosis) -> set[str]:
    return {f.code for f in d.findings}


def test_a_working_connector_is_healthy(db: Database, vault: SecretVault) -> None:
    d = run_diag(db, vault, serve())
    assert d.verdict == "healthy" and d.root_cause is None
    assert {"secret_ok", "dns_ok", "tls_ok", "endpoint_ok", "fields_ok"} <= codes(d)


def test_a_rejected_key_is_named_as_the_cause(db: Database, vault: SecretVault) -> None:
    d = run_diag(db, vault, serve(401, {}))
    assert d.verdict == "broken" and d.root_cause and d.root_cause.code == "auth_rejected"
    assert "hermes secret set" in d.root_cause.fix


def test_a_wrong_path_is_a_404(db: Database, vault: SecretVault) -> None:
    d = run_diag(db, vault, serve(404, {}))
    assert d.root_cause and d.root_cause.code == "endpoint_not_found" and "/advisories" in d.root_cause.fix


def test_server_errors_and_rate_limits_are_told_apart(db: Database, vault: SecretVault) -> None:
    assert run_diag(db, vault, serve(503, {})).root_cause.code == "endpoint_server_error"  # type: ignore[union-attr]
    limited = run_diag(db, vault, serve(429, {}, {"retry-after": "30"}))
    assert limited.root_cause and limited.root_cause.code == "endpoint_rate_limited"
    assert "30" in limited.root_cause.detail


def test_dns_failure_stops_the_live_checks(db: Database, vault: SecretVault) -> None:
    def no_dns(host: str) -> list[str]:
        raise OSError("no such host")

    d = diagnose(make_cfg(BASE), db, vault, resolver=no_dns, tls_check=tls_ok, transport=serve(),
                 sleep=lambda s: None)
    assert d.root_cause and d.root_cause.code == "dns_fail" and "live_skipped" in codes(d)
    assert db.recent_requests("github_advisories") == []  # nothing was sent


def test_a_bad_certificate_is_reported(db: Database, vault: SecretVault) -> None:
    d = diagnose(make_cfg(BASE), db, vault, resolver=resolver_ok,
                 tls_check=lambda h, p: TlsInfo(False, None, "the certificate is not trusted (expired)"),
                 transport=serve(), sleep=lambda s: None)
    assert d.root_cause and d.root_cause.code == "tls_fail"


def test_an_unreachable_server_is_a_network_problem(db: Database, vault: SecretVault) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    d = run_diag(db, vault, httpx.MockTransport(refuse))
    assert d.root_cause and d.root_cause.code == "network_unreachable"


def test_a_missing_key_is_reported_and_nothing_is_sent(db: Database, vault: SecretVault) -> None:
    cfg = make_cfg(BASE, auth={"type": "bearer", "secret": "NOT_STORED"})
    d = diagnose(cfg, db, vault, resolver=resolver_ok, tls_check=tls_ok, transport=serve(), sleep=lambda s: None)
    assert d.root_cause and d.root_cause.code == "secret_missing"
    assert db.recent_requests("github_advisories") == []


def test_a_key_with_a_hidden_space_is_found_and_the_cleaned_key_works(db: Database, vault: SecretVault) -> None:
    vault.store("TEST_TOKEN", chr(0xA0) + FAKE_TOKEN)

    def check(request: httpx.Request) -> httpx.Response:
        ok = request.headers.get("authorization") == f"Bearer {FAKE_TOKEN}"
        return httpx.Response(200 if ok else 401, json=[advisory(1)] if ok else {})

    d = run_diag(db, vault, httpx.MockTransport(check))
    assert d.root_cause and d.root_cause.code == "secret_dirty"
    assert "U+00A0" in d.root_cause.detail
    assert "secret_clean_accepted" in codes(d)  # the API took the cleaned key


def test_a_renamed_field_gets_a_suggestion(db: Database, vault: SecretVault) -> None:
    renamed = [{**advisory(1), "ghsaId": advisory(1)["ghsa_id"]}]
    del renamed[0]["ghsa_id"]
    d = run_diag(db, vault, serve(body=renamed))
    cause = d.root_cause
    assert cause and cause.code == "field_missing" and cause.evidence["suggestion"] == "ghsaId"
    assert "ghsaId" in cause.fix


def test_a_wrong_records_path_is_explained(db: Database, vault: SecretVault) -> None:
    cfg = make_cfg(BASE)
    cfg.endpoints[0].records_path = "items"
    d = diagnose(cfg, db, vault, resolver=resolver_ok, tls_check=tls_ok,
                 transport=serve(body={"data": [advisory(1)]}), sleep=lambda s: None)
    assert d.root_cause and d.root_cause.code == "records_path_missing"
    assert "data" in d.root_cause.evidence["top_level_keys"]


def test_a_web_page_instead_of_json_is_explained(db: Database, vault: SecretVault) -> None:
    html = httpx.MockTransport(lambda r: httpx.Response(200, text="<html>login</html>",
                                                       headers={"content-type": "text/html"}))
    d = run_diag(db, vault, html)
    assert d.root_cause and d.root_cause.code == "reply_not_json"


def test_a_paused_connector_and_a_backlog_are_surfaced(db: Database, vault: SecretVault) -> None:
    db.ensure_connection("github_advisories")
    db.update_connection("github_advisories", paused=1)
    d = run_diag(db, vault, serve())
    assert "connector_paused" in codes(d)


def test_the_diagnosis_is_saved_and_reloads(db: Database, vault: SecretVault) -> None:
    d = run_diag(db, vault, serve(401, {}))
    saved = db.get_diagnosis("github_advisories")
    assert saved and saved["verdict"] == "broken"
    again = Diagnosis.from_json(saved["report"])
    assert again.root_cause and again.root_cause.code == d.root_cause.code  # type: ignore[union-attr]


def test_no_key_appears_in_the_report_or_the_request_record(db: Database, vault: SecretVault) -> None:
    vault.store("TEST_TOKEN", " " + FAKE_TOKEN)
    d = run_diag(db, vault, serve(401, {}))
    blob = d.to_json() + json.dumps(db.recent_requests("github_advisories"))
    assert FAKE_TOKEN not in blob


def test_secret_issue_detection_and_cleaning() -> None:
    assert secret_issues("abc123", "bearer", "secret") == []
    kinds = {c for c, _ in secret_issues(' "Bearer abc"\n', "bearer", "secret")}
    assert {"whitespace", "newline"} <= kinds
    assert clean_secret_value(' "Bearer abc"\n', "bearer", "secret") == "abc"
    assert clean_secret_value("abc", "bearer", "secret") == "abc"  # a clean key is never changed
    assert secret_issues("", "bearer", "secret")[0][0] == "empty"


def test_field_name_suggestions() -> None:
    assert suggest_keys([{"publishedAt": 1}], "published_at") == ["publishedAt"]
    assert suggest_keys([{"unrelated": 1}], "published_at") == []


def test_a_sometimes_missing_field_with_a_default_is_not_a_warning(db: Database, vault: SecretVault) -> None:
    cfg = make_cfg(BASE)
    mapping = cfg.endpoints[0].mapping.fields
    mapping["description"] = mapping["description"].model_copy(update={"from_": "extra"})  # has a default already
    records = [{**advisory(1), "extra": "x"}, advisory(2)]
    d = diagnose(cfg, db, vault, resolver=resolver_ok, tls_check=tls_ok, transport=serve(body=records),
                 sleep=lambda s: None)
    assert "field_optional" in codes(d) and "field_partial" not in codes(d)
    assert d.verdict == "healthy"
