import pytest

from secintegrate import secrets
from secintegrate.config.schema import ConnectorConfig
from secintegrate.storage.db import Database


@pytest.fixture(autouse=True)
def _clean_secrets():
    secrets.clear()
    yield
    secrets.clear()


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")


def make_cfg(base_url: str, **over) -> ConnectorConfig:
    data = {
        "connector": "github_advisories",
        "source": "github",
        "schedule": "*/15 * * * *",
        "base_url": base_url,
        "auth": {"type": "bearer", "secret": "TEST_TOKEN"},
        "endpoints": [{
            "name": "advisories",
            "path": "/advisories",
            "pagination": {"type": "link_header"},
            "incremental": {"cursor_field": "updated_at", "param": "updated",
                            "format": ">={value}", "initial": "2026-01-01"},
            "mapping": {"target": "event", "fields": {
                "id": {"from": "ghsa_id", "required": True},
                "type": {"const": "advisory"},
                "severity": {"from": "severity", "transform": "lower", "default": "unknown"},
                "timestamp": {"from": "published_at", "transform": "iso8601", "required": True},
                "description": {"from": "summary", "default": ""},
            }},
        }],
    }
    data.update(over)
    return ConnectorConfig.model_validate(data)


def advisory(i: int, **over) -> dict:
    rec = {"ghsa_id": f"GHSA-{i}", "severity": "HIGH", "summary": f"s{i}",
           "published_at": "2026-02-01T00:00:00Z", "updated_at": f"2026-03-0{i}T10:00:00Z"}
    rec.update(over)
    return rec
