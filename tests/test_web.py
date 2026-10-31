from __future__ import annotations

from pathlib import Path
from typing import Any

from secintegrate.storage.db import Database
from secintegrate.web.app import create_app


def test_home_shows_summaries_but_not_emails(tmp_path: Path, db: Database) -> None:
    db.upsert("event", "nvd", [{"id": "CVE-1", "type": "cve", "severity": "high",
                               "timestamp": "2026-10-01T00:00:00Z", "description": "<b>bad</b> thing"}],
              "2026-10-31T00:00:00Z")
    db.upsert("user", "github", [{"id": "u1", "name": "Ann", "email": "ann@example.com",
                                  "status": "active", "last_login": None}], "2026-10-31T00:00:00Z")
    client = create_app(tmp_path / "cfg", db).test_client()
    r = client.get("/")
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "CVE-1" in html and "Hermes" in html
    assert "ann@example.com" not in html
    assert "<b>bad</b>" not in html  # descriptions are escaped
    db.upsert("event", "cisa", [{"id": "CVE-2", "type": "kev", "severity": "high",
                                "timestamp": "2026-10-02T00:00:00Z", "description": "other"}], "2026-10-31T00:00:00Z")
    only = client.get("/?source=nvd").get_data(as_text=True)
    assert "CVE-1" in only and "CVE-2" not in only
    assert "CVE-2" in client.get("/?source=cisa").get_data(as_text=True)
    assert "CVE-1" in client.get("/?source=nope").get_data(as_text=True)  # unknown source shows all
    assert "Connector health" in html and "Breakdown" not in html
    assert client.get("/health").headers["Location"].endswith("/")
    form = client.get("/connectors/new")
    assert form.status_code == 200 and "Validate and create" in form.get_data(as_text=True)


def _setup_source(tmp_path: Path, db: Database, status: str, message: str = "") -> Any:
    cfg = tmp_path / "cfg"
    cfg.mkdir(parents=True)
    (cfg / "nvd_cve.yaml").write_text(
        "connector: nvd_cve\nsource: nvd\nschedule: '0 * * * *'\nbase_url: https://example.com\n"
        "auth: {type: none}\nendpoints:\n  - name: e\n    path: /x\n    mapping:\n      target: event\n"
        "      fields:\n        id: {from: id}\n        timestamp: {from: t}\n        severity: {from: s}\n",
        encoding="utf-8")
    db.upsert("event", "nvd", [{"id": "CVE-9", "type": "cve", "severity": "high",
                               "timestamp": "2026-10-01T00:00:00Z", "description": "kept"}], "2026-10-31T00:00:00Z")
    run_id = db.start_run("nvd_cve", "2026-10-31T19:00:00Z")
    db.finish_run(run_id, "success", 1, 0, None)
    db.update_connection("nvd_cve", status=status, message=message)
    return create_app(cfg, db).test_client()


def test_events_stay_visible_but_say_so_when_their_source_is_down(tmp_path: Path, db: Database) -> None:
    client = _setup_source(tmp_path, db, "failing", "Provider is returning server errors. Check its status page.")
    for url in ("/", "/?source=nvd"):
        page = client.get(url).get_data(as_text=True)
        assert "CVE-9" in page  # the earlier records are kept, not hidden
        assert "nvd is unavailable." in page and "may be out of date" in page
        assert "Provider is returning server errors." in page and 'class="flag failing"' in page


def test_no_warning_when_the_source_is_healthy(tmp_path: Path, db: Database) -> None:
    page = _setup_source(tmp_path, db, "healthy").get("/?source=nvd").get_data(as_text=True)
    assert "CVE-9" in page and "may be out of date" not in page and 'class="flag' not in page


def test_warning_names_the_last_good_update_and_other_states(tmp_path: Path, db: Database) -> None:
    page = _setup_source(tmp_path, db, "paused", "Credential rejected.").get("/").get_data(as_text=True)
    assert "nvd is paused." in page and "last good update (2026-" in page
    degraded = _setup_source(tmp_path / "d", db, "degraded").get("/").get_data(as_text=True)
    assert "had a problem on its last update" in degraded


def test_warning_only_covers_the_source_being_viewed(tmp_path: Path, db: Database) -> None:
    client = _setup_source(tmp_path, db, "failing")
    db.upsert("event", "cisa", [{"id": "CVE-1", "type": "kev", "severity": "high",
                                "timestamp": "2026-10-02T00:00:00Z", "description": "x"}], "2026-10-31T00:00:00Z")
    assert "may be out of date" not in client.get("/?source=cisa").get_data(as_text=True)
    assert "nvd is unavailable." in client.get("/").get_data(as_text=True)  # the "All" view still warns
