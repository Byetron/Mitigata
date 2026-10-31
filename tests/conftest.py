from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from secintegrate import secrets
from secintegrate.config.schema import ConnectorConfig
from secintegrate.notify import StateChange
from secintegrate.security.cipher import AesGcmCipher
from secintegrate.security.keybackends import InMemoryKeyBackend
from secintegrate.security.master_key import MasterKeyProvider
from secintegrate.security.repository import SqliteSecretRepository
from secintegrate.security.vault import SecretVault
from secintegrate.storage.db import Database

FAKE_TOKEN = "ghp_test_" + "0000"  # built from parts so CI can grep the repo for the literal


class RecordingNotifier:
    def __init__(self) -> None:
        self.changes: list[StateChange] = []

    def notify(self, change: StateChange) -> None:
        self.changes.append(change)


@pytest.fixture(autouse=True)
def _clean_secrets() -> Iterator[None]:
    secrets.clear()
    yield
    secrets.clear()


@pytest.fixture
def db(tmp_path: Any) -> Database:
    return Database(tmp_path / "test.db")


@pytest.fixture
def vault() -> Iterator[SecretVault]:
    repo = SqliteSecretRepository(":memory:")
    v = SecretVault(MasterKeyProvider(InMemoryKeyBackend()), AesGcmCipher(), repo)
    v.store("TEST_TOKEN", FAKE_TOKEN)
    yield v
    repo.close()


@pytest.fixture
def notifier() -> RecordingNotifier:
    return RecordingNotifier()


def make_cfg(base_url: str, **over: Any) -> ConnectorConfig:
    data: dict[str, Any] = {
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


def advisory(i: int, **over: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {"ghsa_id": f"GHSA-{i}", "severity": "HIGH", "summary": f"s{i}",
                           "published_at": "2026-02-01T00:00:00Z", "updated_at": f"2026-03-0{i}T10:00:00Z"}
    rec.update(over)
    return rec
