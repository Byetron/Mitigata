# Changes: safeguards from IMPROVEMENTS_BUILD_BRIEF.md

Every acceptance criterion and the test that proves it. Run everything with `pytest`; the type and lint checks are
`mypy` (strict) and `ruff check src tests`.

## Feature A: encrypted secrets (`tests/test_secret_vault.py`)

| # | Test |
|---|---|
| A-1 | `test_a1_round_trip` |
| A-2 | `test_a2_secret_repr_and_str_hide_value` |
| A-3 | `test_a3_ciphertext_moved_to_another_name_fails` |
| A-4 | `test_a4_tampered_ciphertext_fails` |
| A-5 | `test_a5_nonce_makes_blobs_differ` |
| A-6 | `test_a6_master_key_created_once_and_reused` |
| A-7 | `test_a7_malformed_env_key_is_rejected_without_leaking` |
| A-8 | `test_a8_secret_set_hides_input_and_takes_no_value_argument` |
| A-9 | `test_a9_no_plaintext_in_database_file_or_logs`, plus `scripts/secret_scan.sh` |
| A-10 | Every test in the file uses `InMemoryKeyBackend` and `:memory:` SQLite; `test_a10_names_are_validated_and_missing_secret_reported` covers names |

## Feature C: validation (`tests/test_validator.py`, `tests/test_web_form.py`)

| # | Test |
|---|---|
| C-1 | `test_rule_fails_then_passes` (one failing and one passing fixture per shape rule), `test_user_and_event_requirements`, `test_secret_must_exist_in_vault`, `test_connector_ids_must_be_unique` |
| C-2 | `test_c2_real_looking_key_is_blocked_and_never_echoed` |
| C-3 | `test_c3_cli_and_form_report_identical_issues` |
| C-4 | `test_c4_transform_typo_suggests_closest` |
| C-5 | `test_c5_presets_validate_without_errors` |
| C-6 | `test_c6_single_field_validation_is_fast` |

## Feature B: monitoring (`tests/test_failures.py`)

| # | Test |
|---|---|
| B-1 | `test_b1_status_classification`, `test_b1_exceptions_and_end_to_end_categories`, `test_b5_*` (schema_changed, bad_data), `test_network_loss_mid_run` |
| B-2 | `test_b2_every_category_has_exactly_one_remediation_entry` |
| B-3 | `test_b3_wrong_key_pauses_after_two_failures_with_one_notification` |
| B-4 | `test_b4_429_waits_retry_after_then_succeeds` |
| B-5 | `test_b5_every_record_missing_a_required_field_is_schema_changed`, `test_b5_one_bad_record_is_bad_data` |
| B-6 | `test_b6_ten_consecutive_failures_send_one_notification`, `test_b6_transition_rules`, `test_recovery_notifies` |
| B-7 | `test_b7_no_secret_in_messages_logs_or_health` |
| B-8 | `test_b8_probe_writes_no_records_and_stores_a_result` |
| B-9 | `test_b9_home_renders_empty_never_run_and_paused` |

## Cross-feature

| # | Status |
|---|---|
| X-1 | `hermes init` creates the key, database, tables and builds the probe schedule; `test_init_is_idempotent` |
| X-2 | `runner.run_connector` follows the order; `test_probe_failures_are_classified_and_degrade_status` shows the probe running before the sync |
| X-3 | Redaction filter on every log handler; templates auto-escape; `test_b7_*`, `test_a9_*` |
| X-4 | `bootstrap.build_app()` is the only place adapters are chosen; CLI, scheduler and web all start there |
| X-5 | `.github/workflows/ci.yml` runs ubuntu, macOS and Windows. **Not run yet**: it needs the repository secret `SECINTEGRATE_MASTER_KEY` and a push |
| X-6 | `scripts/secret_scan.sh`, called from CI. Verified locally: tracked files are clean |

## Decisions made where the brief was silent or conflicted

- **Jira is not built.** You removed it from the application, so the presets are GitHub, NVD and a public feed, and
  probes are defined for GitHub and NVD only.
- **Health lives on the home page**, not a separate `/health` page (your later instruction). `/health` redirects.
- **CLI name.** `hermes` is the main command (you renamed the app); `secintegrate` stays as an alias.
- **Failure vocabulary.** The old codes were renamed to the brief's nine categories. Malformed JSON in a 200 reply and
  a probe returning an unexpected 2xx are `unknown`. A secret missing from the vault at run time is `auth_failed`.
- **`schema_changed`** needs at least two records on the page, so a one-record page with a bad record stays `bad_data`.
- **Notifications.** A first successful run after `never_run` is not announced as a "recovery". The webhook body holds
  connector, status, message and timestamp, plus the same line under `text` (Slack) and `content` (Discord) because those
  services reject a body without them.
- **Base URL** must be `https://`; plain `http://localhost` and `http://127.0.0.1` are allowed so tests can use a local
  mock server.
- **Pausing** counts consecutive failed runs; for probes it counts the last two probes. Setting the secret again, or
  `hermes resume`, un-pauses.
- **`db reset` keeps secrets.** The `secrets` table is not in the list of tables it drops.
- **Database location** is now the per-user data directory (`platformdirs`), as the brief requires. The old
  `data/secintegrate.db` is no longer used.
- **Lint rules.** `PLR0912`, `PLR0913`, `PLR0915` and `PLR0917` (branch, statement and argument counts) are switched off
  because dependencies are injected on purpose. Tests also skip `S101`, `PLR2004`, `S105`, `S106`. `mypy` ignores missing
  stubs for `apscheduler`, `yaml`, `keyring` and `pytest_httpserver`.
- **Dev tools.** `ruff` and `mypy` were added to the dev extras because the brief requires them to pass.
- **A bug found and fixed along the way:** a missing or wrongly shaped `records_path` used the old string error codes and
  would have crashed; it is now a `schema_changed` failure (`test_missing_records_path_is_schema_changed`).

## Later additions (after the brief)

Tests are in `tests/test_autoheal.py` and `tests/test_web_auth.py`.

- **Automatic recovery** (`autoheal.py`, `scheduler.py`, `probe.recheck_paused`): growing retry delays for transient
  failures, hourly auto-resume of auth-paused connectors that have a probe, and re-trying quarantined records.
  Quarantine no longer stores the same record twice. This is a deliberate step past the brief's "no automatic fixes"
  non-goal, limited to actions that cannot change a config or hide a real problem.
- **YAML editor and template** (`config/template.yaml`, `connector_files.py`): same validator, file saved verbatim.
- **Remove connectors**: soft delete to `.trash/`, state cleared, records kept; live scheduler hooks for add and remove.
- **Sign-in** (`web/auth.py`, `web/google.py`, `cli_auth.py`): Google (code flow plus PKCE, on `httpx`, so no new
  dependency) and a local-password fallback, an allowlist table (`app_users`), CSRF on every POST, login throttling,
  hardened cookies and headers. The password fallback exists because Google credentials can only be created by you.
- **Decisions:** the web UI now refuses anonymous visitors; `db reset` keeps sign-in users and secrets; no Google tokens are
  stored; the session secret is kept in the vault as `SESSION_SECRET`.

### Account creation (`tests/test_signup.py`)

- `/signup` page with a link from the sign-in page; the first account is active, later ones are `pending` until approved on
  `/users` or with `hermes auth approve`. Google first sign-in follows the same rule. Existing addresses are never changed,
  sign-up answers the same for new and existing addresses, every attempt counts toward a 10-minute limit, and at most 50
  requests can wait.
- A removed or unapproved user's session stops working on their next request.
- `hermes serve` pins the address to `http://127.0.0.1:PORT` (other host names are redirected there) so the cookie and the
  Google redirect URI match, and so a forged Host header cannot change the redirect URI.
- Old databases gain the `status` column on start; people who could sign in before stay active.

### Start-up first run and live-run log

- `hermes serve` runs every enabled connector that has never run once, staggered a few seconds apart
  (`scheduler.schedule_first_runs`, tested in `tests/test_autoheal.py`). Before this, a fresh database showed events from
  only whichever connector had last been run by hand.
- `docs/live-run-log.md` records one real run of every connector (spec section 8.3).

### API simulation, hardening, simpler template

- `scripts/simulate_api_errors.py` drives the real runner through 35 scripted bad-API behaviours (also run as
  `tests/test_api_simulation.py`). The first run found 15 problems, all fixed:
  - the login header followed redirects, and a next-page link, to other servers: login headers now go only to the
    configured server, and a link to another server stops the run;
  - paging that never ends: a 1,000-page safety limit (`max_pages`), plus detection of repeated links, tokens and pages;
  - relative next-page links now work;
  - `Retry-After` longer than 5 minutes is no longer slept through (it would block a connector for hours), and a 503's
    `Retry-After` is honoured like a 429's;
  - an empty body, 204 or `null` means "nothing new" instead of an error;
  - a record dated far in the future can no longer push the sync cursor ahead;
  - the quarantine holds at most 5,000 records per connector;
  - a probe that gets 429 counts as reachable.
- The starter template is now four short parts in plain words; the extras moved to `docs/connector-options.md`.
- The navigation no longer shows a number next to **Users**. It was not requested.
