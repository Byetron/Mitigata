"""Feature A acceptance tests (A-1 to A-10). No network, no OS keychain, no real keys."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secintegrate.cli import app
from secintegrate.security.cipher import AesGcmCipher
from secintegrate.security.errors import (
    DecryptionError,
    InvalidSecretNameError,
    KeyStoreUnavailableError,
    SecretNotFoundError,
)
from secintegrate.security.keybackends import EnvKeyBackend, InMemoryKeyBackend
from secintegrate.security.master_key import MasterKeyProvider
from secintegrate.security.repository import SqliteSecretRepository
from secintegrate.security.vault import SecretVault

FAKE = "ghp_test_" + "0000"  # built from parts so CI can grep the repo for the literal


def make_vault(db: str | Path = ":memory:") -> SecretVault:
    return SecretVault(MasterKeyProvider(InMemoryKeyBackend()), AesGcmCipher(), SqliteSecretRepository(db))


def test_a1_round_trip() -> None:
    vault = make_vault()
    vault.store("GITHUB_TOKEN", FAKE)
    assert vault.load("GITHUB_TOKEN").reveal() == FAKE


def test_a2_secret_repr_and_str_hide_value() -> None:
    vault = make_vault()
    vault.store("GITHUB_TOKEN", FAKE)
    secret = vault.load("GITHUB_TOKEN")
    assert FAKE not in repr(secret) and FAKE not in str(secret) and FAKE not in f"{secret}"


def test_a3_ciphertext_moved_to_another_name_fails() -> None:
    repo = SqliteSecretRepository(":memory:")
    vault = SecretVault(MasterKeyProvider(InMemoryKeyBackend()), AesGcmCipher(), repo)
    vault.store("GITHUB_TOKEN", FAKE)
    repo.put("OTHER_TOKEN", repo.get("GITHUB_TOKEN"))
    with pytest.raises(DecryptionError):
        vault.load("OTHER_TOKEN")


def test_a4_tampered_ciphertext_fails() -> None:
    repo = SqliteSecretRepository(":memory:")
    vault = SecretVault(MasterKeyProvider(InMemoryKeyBackend()), AesGcmCipher(), repo)
    vault.store("GITHUB_TOKEN", FAKE)
    blob = bytearray(repo.get("GITHUB_TOKEN"))
    blob[-1] ^= 0x01
    repo.put("GITHUB_TOKEN", bytes(blob))
    with pytest.raises(DecryptionError):
        vault.load("GITHUB_TOKEN")


def test_a5_nonce_makes_blobs_differ() -> None:
    cipher, key = AesGcmCipher(), bytes(32)
    assert cipher.encrypt(key, "A", FAKE) != cipher.encrypt(key, "A", FAKE)


def test_a6_master_key_created_once_and_reused() -> None:
    backend = InMemoryKeyBackend()
    first = MasterKeyProvider(backend).get_or_create()
    assert len(first) == 32
    assert MasterKeyProvider(backend).get_or_create() == first


@pytest.mark.parametrize("bad", ["not-hex-" + "z" * 8, "ab" * 5, "ab" * 40])
def test_a7_malformed_env_key_is_rejected_without_leaking(bad: str) -> None:
    provider = MasterKeyProvider(EnvKeyBackend({"SECINTEGRATE_MASTER_KEY": bad}))
    with pytest.raises(KeyStoreUnavailableError) as info:
        provider.get_or_create()
    assert bad not in str(info.value)


def test_a8_secret_set_hides_input_and_takes_no_value_argument(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ab" * 32)
    prompts: list[str] = []

    def fake_getpass(prompt: str = "") -> str:
        prompts.append(prompt)
        return FAKE

    monkeypatch.setattr("secintegrate.cli_secrets.getpass.getpass", fake_getpass)
    db = str(tmp_path / "t.db")
    runner = CliRunner()
    result = runner.invoke(app, ["secret", "set", "GITHUB_TOKEN", "--db", db])
    assert result.exit_code == 0 and FAKE not in result.output and len(prompts) == 2
    # there is no way to pass the value on the command line
    rejected = runner.invoke(app, ["secret", "set", "GITHUB_TOKEN", FAKE, "--db", db])
    assert rejected.exit_code != 0
    listing = runner.invoke(app, ["secret", "list", "--db", db])
    assert "GITHUB_TOKEN" in listing.output and FAKE not in listing.output


def test_a9_no_plaintext_in_database_file_or_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    db = tmp_path / "t.db"
    with caplog.at_level(logging.DEBUG):
        vault = make_vault(db)
        vault.store("GITHUB_TOKEN", FAKE)
        vault.load("GITHUB_TOKEN")
    assert FAKE.encode() not in db.read_bytes()
    assert FAKE not in caplog.text


def test_a10_names_are_validated_and_missing_secret_reported() -> None:
    vault = make_vault()
    for bad in ("github_token", "1ABC", "A-B", ""):
        with pytest.raises(InvalidSecretNameError):
            vault.store(bad, FAKE)
    with pytest.raises(SecretNotFoundError):
        vault.load("MISSING_ONE")
    vault.store("GITHUB_TOKEN", FAKE)
    vault.store("GITHUB_TOKEN", FAKE + "2")  # upsert
    assert vault.list_names() == ["GITHUB_TOKEN"]
    assert vault.load("GITHUB_TOKEN").reveal() == FAKE + "2"
    vault.delete("GITHUB_TOKEN")
    assert vault.list_names() == []


def test_import_env_stores_names_and_never_prints_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "cd" * 32)
    env = tmp_path / "fake.env"
    env.write_text(f"GITHUB_TOKEN={FAKE}\nEMPTY_ONE=\nlower_case=x\n", encoding="utf-8")
    db = str(tmp_path / "t.db")
    result = CliRunner().invoke(app, ["secret", "import-env", str(env), "--db", db])
    assert result.exit_code == 0 and "GITHUB_TOKEN" in result.output and FAKE not in result.output
    assert "EMPTY_ONE" not in result.output and "NOT deleted" in result.output
    assert env.exists()


def test_init_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECINTEGRATE_MASTER_KEY", "ef" * 32)
    db = str(tmp_path / "t.db")
    runner = CliRunner()
    for _ in range(2):
        result = runner.invoke(app, ["init", "--db", db])
        assert result.exit_code == 0 and "ef" * 32 not in result.output
