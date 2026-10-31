from secintegrate.web.app import create_app


def test_home_shows_summaries_but_not_emails(tmp_path, db):
    db.upsert("event", "nvd", [{"id": "CVE-1", "type": "cve", "severity": "high",
                               "timestamp": "2026-10-01T00:00:00Z", "description": "<b>bad</b> thing"}],
              "2026-10-31T00:00:00Z")
    db.upsert("user", "github", [{"id": "u1", "name": "Ann", "email": "ann@example.com",
                                  "status": "active", "last_login": None}], "2026-10-31T00:00:00Z")
    client = create_app(tmp_path / "cfg", db).test_client()
    r = client.get("/")
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "CVE-1" in html and "Security Integration Overview" in html
    assert "ann@example.com" not in html
    assert "<b>bad</b>" not in html          # descriptions are escaped
    db.upsert("event", "cisa", [{"id": "CVE-2", "type": "kev", "severity": "high",
                                "timestamp": "2026-10-02T00:00:00Z", "description": "other"}], "2026-10-31T00:00:00Z")
    only = client.get("/?source=nvd").get_data(as_text=True)
    assert "CVE-1" in only and "CVE-2" not in only
    assert "CVE-2" in client.get("/?source=cisa").get_data(as_text=True)
    assert "CVE-1" in client.get("/?source=nope").get_data(as_text=True)   # unknown source shows all
    assert "Connector health" in html and "Breakdown" not in html
    assert client.get("/health").headers["Location"].endswith("/")
    form = client.get("/connectors/new")
    assert form.status_code == 200 and "Validate and create" in form.get_data(as_text=True)
