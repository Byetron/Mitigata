"""Feature C validator tests (C-1 to C-4): one failing and one passing fixture per rule."""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from secintegrate.cli import app
from secintegrate.config.validator import has_errors, validate_text

GOOD = """connector: demo
source: demo
schedule: "*/5 * * * *"
base_url: https://example.com
auth: {type: bearer, secret: DEMO_TOKEN}
probe: {path: /ping}
endpoints:
  - name: e
    path: /x
    mapping:
      target: event
      fields:
        id: {from: id, required: true}
        timestamp: {from: ts, required: true}
        severity: {from: sev, default: unknown}
"""
SECRETS = {"DEMO_TOKEN", "OTHER_ONE"}
REAL_LOOKING = "ghp_" + "a1B2c3D4e5F6g7H8i9J0"


def check(text: str, **kw: object) -> list[str]:
    known = kw.pop("known_secrets", SECRETS)
    _, issues = validate_text(text, "t.yaml", known_secrets=known, **kw)  # type: ignore[arg-type]
    return [f"{i.path}: {i.message}" for i in issues if i.severity == "error"]


def test_good_config_has_no_errors() -> None:
    assert check(GOOD) == []


# (rule, text before, text after for the failing fixture, text after for the passing fixture, message fragment)
RULES = [
    ("connector id", "connector: demo", "connector: Demo-1", "connector: d2",
     "Use 2 to 41 lowercase letters, digits, or underscores, starting with a letter."),
    ("schedule", '"*/5 * * * *"', '"*/5 * *"', '"0 0 * * *"', "Schedule needs 5 fields, for example `*/15 * * * *`."),
    ("base url", "https://example.com", "http://example.com", "https://example.org",
     "Base URL must start with https://."),
    ("secret name", "secret: DEMO_TOKEN", "secret: demo_token", "secret: OTHER_ONE",
     "Enter the environment variable name, not the key. Example: GITHUB_TOKEN."),
    ("real key", "secret: DEMO_TOKEN", f"secret: {REAL_LOOKING}", "secret: DEMO_TOKEN",
     "This looks like a real key. Store it with `secintegrate secret set`, then enter its name here."),
    ("path", "path: /x", "path: x", "path: /y", "Path must start with /."),
    ("pagination type", "path: /x", "path: /x\n    pagination: {type: bogus}",
     "path: /x\n    pagination: {type: link_header}", "Pick one of: link_header, offset, page_number, cursor."),
    ("mapping target", "target: event", "target: gadget", "target: event", "Target must be user, device, or event."),
    ("transform name", "severity: {from: sev, default: unknown}",
     "severity: {from: sev, default: unknown, transform: lowr}",
     "severity: {from: sev, default: unknown, transform: lower}", "Unknown transform `lowr`. Did you mean `lower`?"),
    ("offset fields", "path: /x", "path: /x\n    pagination: {type: offset}",
     "path: /x\n    pagination: {type: offset, start_param: a, limit_param: b}",
     "Offset paging needs a start parameter and a limit parameter."),
    ("link header start_param", "path: /x", "path: /x\n    pagination: {type: link_header, start_param: s}",
     "path: /x\n    pagination: {type: link_header}",
     "Link-header paging follows URLs from the server. Remove `start_param`."),
    ("incremental methods", "path: /x",
     "path: /x\n    incremental: {cursor_field: u, initial: '2026-01-01', param: p, start_param: s, end_param: e}",
     "path: /x\n    incremental: {cursor_field: u, initial: '2026-01-01', param: p}", "Choose one incremental method."),
    ("required with default", "id: {from: id, required: true}", "id: {from: id, required: true, default: x}",
     "id: {from: id, required: true}", "Field `id` is marked required but also has a default. Remove one."),
]


@pytest.mark.parametrize(("rule", "before", "bad", "good", "fragment"), RULES, ids=[r[0] for r in RULES])
def test_rule_fails_then_passes(rule: str, before: str, bad: str, good: str, fragment: str) -> None:
    assert before in GOOD, rule
    failing = check(GOOD.replace(before, bad))
    assert any(fragment in m for m in failing), (rule, failing)
    assert check(GOOD.replace(before, good)) == [], rule


def test_user_and_event_requirements() -> None:
    no_name = GOOD.replace("target: event", "target: user").replace("severity:", "email:").replace(
        "timestamp: {from: ts, required: true}", "status: {from: s, default: x}")
    assert any("A user record needs `id` and `name`." in m for m in check(no_name))
    with_name = no_name.replace("status:", "name:")
    assert check(with_name) == []
    no_severity = GOOD.replace("        severity: {from: sev, default: unknown}\n", "")
    assert any("An event record needs `id`, `timestamp`, and `severity`." in m for m in check(no_severity))


def test_secret_must_exist_in_vault() -> None:
    assert any("Secret `DEMO_TOKEN` is not stored. Run `secintegrate secret set DEMO_TOKEN`." in m
               for m in check(GOOD, known_secrets=set()))
    assert check(GOOD, known_secrets=None) == []  # check skipped when no vault is given


def test_connector_ids_must_be_unique() -> None:
    assert any("defined in two files" in m for m in check(GOOD, known_ids={"demo"}))


def test_c4_transform_typo_suggests_closest() -> None:
    bad = GOOD.replace("severity: {from: sev, default: unknown}", "severity: {from: sev, default: x, transform: strp}")
    assert any("Did you mean `strip`?" in m for m in check(bad))


def test_missing_probe_is_a_warning_not_an_error() -> None:
    text = GOOD.replace("probe: {path: /ping}\n", "")
    _, issues = validate_text(text, "t.yaml", known_secrets=SECRETS)
    assert [i.severity for i in issues] == ["warning"] and not has_errors(issues)


def test_errors_carry_line_numbers() -> None:
    _, issues = validate_text(GOOD.replace("path: /x", "path: x"), "t.yaml", known_secrets=SECRETS)
    assert issues[0].line == 9 and issues[0].path == "endpoints[0].path"


def test_cli_validate_exit_codes_and_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    db = str(tmp_path / "t.db")
    runner = CliRunner()
    runner.invoke(app, ["init", "--db", db])
    from secintegrate.security.factory import build_vault

    build_vault(db).store("DEMO_TOKEN", "fake-value-0000")
    good = tmp_path / "good.yaml"
    good.write_text(GOOD, encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text(GOOD.replace("path: /x", "path: x"), encoding="utf-8")
    ok = runner.invoke(app, ["validate", str(good), "--db", db])
    assert ok.exit_code == 0
    fail = runner.invoke(app, ["validate", str(bad), "--db", db])
    assert fail.exit_code == 1 and "bad.yaml:9 endpoints[0].path: Path must start with /." in fail.output
    warn_only = tmp_path / "warn.yaml"
    warn_only.write_text(GOOD.replace("probe: {path: /ping}\n", ""), encoding="utf-8")
    assert runner.invoke(app, ["validate", str(warn_only), "--db", db]).exit_code == 0
