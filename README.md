# Hermes

Hermes is a config-driven security integration platform. Each source is one YAML file in `config/connectors/`;
no code changes are needed to add a source. See `PLATFORM_SPEC.md` for the base design and
`IMPROVEMENTS_BUILD_BRIEF.md` for the safeguards (encrypted secrets, monitoring, input validation).

## Connectors

| Connector | Source | Auth | Paging | Lands in |
|---|---|---|---|---|
| `github_advisories` | GitHub Security Advisories | bearer token | link header | events |
| `nvd_cve` | NIST NVD CVE API 2.0 | API key header | offset | events |
| `cisa_kev` | CISA Known Exploited Vulnerabilities | none | single request | events |
| `epss_high_risk` | FIRST EPSS (score above 0.9) | none | offset | events |
| `hibp_breaches` | Have I Been Pwned breach list | none | single request | events |
| `feodo_c2` | abuse.ch Feodo botnet C2 IPs | none | single request | devices |

## First run

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

hermes init                      # creates the master key (OS keychain) and the database. Safe to repeat.
hermes secret set GITHUB_TOKEN   # typed at a hidden prompt, never as an argument
hermes secret set NVD_API_KEY
hermes secret list               # names and update times only
hermes validate                  # errors block running; warnings (for example "no probe") do not
hermes serve                     # scheduler + dashboard on http://127.0.0.1:8000
```

Coming from the old plaintext `.env`? Run `hermes secret import-env .env` once, then **delete `.env` and rotate
those keys at the provider**. Hermes no longer reads `.env` at runtime. `.env.example` is only a list of names.

On a headless machine with no OS keychain, set `SECINTEGRATE_MASTER_KEY` to 64 hex characters
(for example `python -c "import os; print(os.urandom(32).hex())"`) and keep it in your secret manager.

## Everyday commands

```powershell
hermes run nvd_cve --once        # one run now; prints pages, requests, records
hermes status                    # health table in the terminal
hermes resume github_advisories  # un-pause a connector (also happens when you set its secret again)
hermes secret delete NAME
hermes db reset --yes            # wipes fetched data only; stored secrets are kept
pytest ; ruff check src tests ; mypy
```

`secintegrate` still works as an alias for `hermes`.

## Adding a connector

1. Open `http://127.0.0.1:8000/connectors/new`.
2. Click a preset (GitHub advisories, NVD CVEs, or a public feed with no key) and edit it, or fill in the form.
   Each field is checked as you leave it, with the same rules as `hermes validate`.
3. Fields take the **name** of a stored secret, never a key. A pasted key is rejected and not echoed back.
4. Submit. A valid file is written to `config/connectors/` and starts running after the next `hermes serve`.

A source starting with `=` in a mapping row is a fixed value, for example `=high`.

## Monitoring

Each connector can declare a `probe` (one cheap request, no data written, for example `GET /user`). The home page
shows, per connector: status, last run, records, quarantined count, a plain-English message, failures in a row, and
the last 24 probe results. Failures fall into nine fixed categories (`auth_failed`, `not_found`, `rate_limited`,
`server_error`, `network`, `schema_changed`, `bad_data`, `client_error`, `unknown`), each with one fixed action and
one fixed message. Two auth failures in a row pause the connector. Notifications fire only on state changes. To get
Slack or Discord alerts, store a webhook URL with `hermes secret set NOTIFY_WEBHOOK_URL`.

## Security model

**Protected**
- API keys are encrypted at rest with AES-256-GCM. Each value gets a fresh random nonce, and the secret's name is
  bound to the ciphertext, so a value copied to another name will not decrypt.
- The master key lives in the OS keychain, or in `SECINTEGRATE_MASTER_KEY` on headless machines.
- Keys are never in config files, logs, the dashboard, error messages or notifications.
- The web UI binds to `127.0.0.1` only.

**Not protected**
- Anyone with administrator access to your unlocked account can read the keychain. That is the trust boundary.
- Python cannot guarantee decrypted values are wiped from memory. The protection is against leaks through logs and
  tracebacks, not against memory inspection.
- Losing the master key makes every stored secret unrecoverable. **Back it up:** on a machine with a keychain,
  export it once into a password manager. The key is stored under service `secintegrate`, account `master`.
- The rest of the database (fetched records) is not encrypted.

## Notes

- GitHub's `updated=>=...` filter syntax should be confirmed with one request (spec risk table).
- `incremental.cursor_format` and `lookback_minutes` are small additions to the spec's format, needed because NVD
  wants non-ISO timestamps.
- Data lives in your per-user data directory (printed by `hermes init`), not in the project folder.
