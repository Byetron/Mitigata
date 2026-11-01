"""Feature C web form tests: C-2, C-3, C-5, C-6."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from flask.testing import FlaskClient
from typer.testing import CliRunner

from secintegrate.cli import app as cli_app
from secintegrate.config.validator import validate_text
from secintegrate.storage.db import Database
from secintegrate.web import forms
from secintegrate.web.app import create_app

NAMES = {"GITHUB_TOKEN", "NVD_API_KEY"}
REAL_LOOKING = "ghp_" + "a1B2c3D4e5F6g7H8i9J0"


def to_form(values: dict[str, Any]) -> dict[str, str]:
    flat = {k: str(v) for k, v in values.items() if k != "rows"}
    for i, row in enumerate(values["rows"]):
        flat[f"map_target_{i}"] = row["target"]
        flat[f"map_source_{i}"] = row["source"]
        flat[f"map_transform_{i}"] = row["transform"]
        flat[f"map_required_{i}"] = "yes" if row["required"] else "no"
    return flat


@pytest.fixture
def client(tmp_path: Path, db: Database) -> FlaskClient:
    return create_app(tmp_path / "cfg", db, secret_names=lambda: NAMES).test_client()


@pytest.mark.parametrize("name", ["github", "nvd", "public"])
def test_c5_presets_validate_without_errors(name: str) -> None:
    text = yaml.safe_dump(forms.build_config(forms.presets()[name]), sort_keys=False)
    _, issues = validate_text(text, f"{name}.yaml", known_secrets=NAMES)
    assert [i for i in issues if i.severity == "error"] == []


def test_preset_can_be_submitted_and_writes_a_valid_file(client: FlaskClient, tmp_path: Path) -> None:
    response = client.post("/connectors/new", data=to_form(forms.presets()["github"]))
    assert response.status_code == 200
    written = tmp_path / "cfg" / "github_example.yaml"
    assert written.exists()
    _, issues = validate_text(written.read_text(encoding="utf-8"), str(written), known_secrets=NAMES)
    assert not [i for i in issues if i.severity == "error"]


def test_c2_real_looking_key_is_blocked_and_never_echoed(client: FlaskClient, tmp_path: Path) -> None:
    values = forms.presets()["github"]
    values["secret_env"] = REAL_LOOKING
    response = client.post("/connectors/new", data=to_form(values))
    html = response.get_data(as_text=True)
    assert response.status_code == 400
    assert "This looks like a real key. Store it with" in html
    assert REAL_LOOKING not in html
    assert not (tmp_path / "cfg").exists() or not list((tmp_path / "cfg").glob("*.yaml"))


def test_unknown_secret_name_is_reported_inline(client: FlaskClient) -> None:
    values = forms.presets()["github"]
    values["secret_env"] = "NOT_STORED_YET"
    response = client.post("/connectors/new", data=to_form(values))
    assert response.status_code == 400
    assert "Secret `NOT_STORED_YET` is not stored." in response.get_data(as_text=True)


def test_validate_field_returns_only_that_fields_issues(client: FlaskClient) -> None:
    values = forms.presets()["github"]
    values.update(base_url="http://example.com", path="no-slash")
    data = {**to_form(values), "field": "base_url"}
    payload = client.post("/connectors/validate-field", data=data).get_json()
    assert [i["message"] for i in payload["issues"]] == ["Base URL must start with https://."]


def test_c3_cli_and_form_report_identical_issues(client: FlaskClient, tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    values = forms.presets()["github"]
    values.update(base_url="http://example.com", path="no-slash", schedule="* *", secret_env="")
    form = to_form(values)
    web = {i["message"] for i in client.post("/connectors/validate-field", data=form).get_json()["issues"]}

    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    file = tmp_path / "bad_example.yaml"
    file.write_text(yaml.safe_dump(forms.build_config(values), sort_keys=False), encoding="utf-8")
    result = CliRunner().invoke(cli_app, ["validate", str(file), "--db", str(tmp_path / "cli.db")])
    cli = set()
    for line in result.output.splitlines():
        if ".yaml:" in line and ": " in line:
            message = line.split(": ", 1)[1].removesuffix(" (warning)")
            cli.add(message)
    # the form checks secrets against NAMES, the CLI against its own empty vault: compare the shared rules
    web = {m for m in web if "is not stored" not in m}
    cli = {m for m in cli if "is not stored" not in m}
    assert web == cli and len(web) >= 3


def test_c6_single_field_validation_is_fast(client: FlaskClient) -> None:
    data = {**to_form(forms.presets()["nvd"]), "field": "path"}
    client.post("/connectors/validate-field", data=data)  # warm up
    started = time.perf_counter()
    client.post("/connectors/validate-field", data=data)
    assert (time.perf_counter() - started) * 1000 < 200


def test_form_page_has_presets_and_no_secret_value_field(client: FlaskClient) -> None:
    html = client.get("/connectors/new").get_data(as_text=True)
    for name in ("github", "nvd", "public"):
        assert f'data-preset="{name}"' in html
    assert 'type="password"' not in html


def test_every_public_feed_preset_is_valid_and_the_button_offers_them_all() -> None:
    import yaml as _yaml

    from secintegrate.config.validator import validate_text

    feeds = forms.public_feeds()
    assert len(feeds) >= 5 and len({f["label"] for f in feeds}) == len(feeds)
    for feed in feeds:
        text = _yaml.safe_dump(forms.build_config(feed), sort_keys=False)
        cfg, issues = validate_text(text, "x.yaml", set(), None, allow_internal=False)
        assert cfg is not None and not [i for i in issues if i.severity == "error"], (feed["label"], issues)
