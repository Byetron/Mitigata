# Hermes

Hermes is a config-driven security integration platform. Each source is one YAML file in `config/connectors/`;
no code changes are needed to add a source. It fetches on a schedule, stores records in a local database, and shows
each connector's health on a local dashboard. See `PLATFORM_SPEC.md` for the design and `CHANGES.md` for the history.

Requires Python 3.11 or newer. Works on Windows, macOS and Linux.

## Connectors

These ship in `config/connectors/`:

| Connector | Source | Auth | Paging | Lands in |
|---|---|---|---|---|
| `github_advisories` | GitHub Security Advisories | bearer token | link header | events |
| `nvd_cve` | NIST NVD CVE API 2.0 | API key header | offset | events |
| `epss_high_risk` | FIRST EPSS (score above 0.9) | none | offset | events |
| `feodo_c2` | abuse.ch Feodo botnet C2 IPs | none | single request | devices |

More sources (for example CISA Known Exploited Vulnerabilities) are available as presets on the **Add connector** page.

## First run

```powershell
python -m venv .venv
.venv\Scripts\activate          # macOS / Linux: source .venv/bin/activate
pip install -e ".[dev]"

hermes init                      # creates the master key (OS keychain) and the database. Safe to repeat.
hermes secret set GITHUB_TOKEN   # typed at a hidden prompt, never as an argument
hermes secret set NVD_API_KEY
hermes secret list               # names and update times only
hermes validate                  # errors block running; warnings (for example "no probe") do not
hermes auth set-password you@example.com   # who may sign in (see "Signing in" below)
hermes serve                     # scheduler + dashboard on http://127.0.0.1:8000
```

On Windows, `run.bat` wraps the server: `run start` (opens the browser), `run stop`, `run restart`, `run status`, `run test`.

Coming from the old plaintext `.env`? Run `hermes secret import-env .env` once, then **delete `.env` and rotate
those keys at the provider**. Hermes no longer reads `.env` at runtime. `.env.example` is only a list of names.

On a headless machine with no OS keychain, set `SECINTEGRATE_MASTER_KEY` to 64 hex characters
(for example `python -c "import os; print(os.urandom(32).hex())"`) and keep it in your secret manager.

## Everyday commands

```powershell
hermes run nvd_cve --once        # one run now; prints pages, requests, records
hermes status                    # health table in the terminal
hermes resume github_advisories  # un-pause a connector (also happens when you set its secret again)
hermes diagnose nvd_cve          # check config, key, network and the live API; says what is wrong and how to fix it
hermes repair nvd_cve            # diagnose, apply the safe automatic fixes, then check again
hermes tools                     # list the inspect/repair tools and whether each changes state
hermes secret delete NAME
hermes db reset --yes            # wipes fetched data only; stored secrets are kept
pytest ; ruff check src tests ; mypy
```

`secintegrate` still works as an alias for `hermes`.

## Accounts and sign-in

Anyone who can reach the dashboard can create an account on the sign-in page: **Create account**, or **Continue with
Google**. There is no approval step.

**A small maths question guards every way in.** The sign-in and sign-up pages both show a question such as "What is 7
plus 5?" at the bottom of the form, below the buttons, and the answer is required by all three: **Sign in** (or **Create
account**) and the **Google** button below it. Google is a form button rather than a link, so it only starts when you click
it, and never without the answer (a wrong or empty answer returns to the page with a message and a new question). Pressing
Enter in the email or password box always uses the main button, never Google. The answer is checked before the password is looked at, so a wrong
answer reveals nothing about whether a password was right. A hidden trap field catches simple programs, and wrong answers
count toward the same limit as wrong passwords. This stops casual bots, not a determined attacker, so keep Hermes on
`127.0.0.1`, where only people on this computer can reach it. Coming back from Google needs no second question.

**Every account has its own workspace.** A new account starts empty: it sees only the connectors, records, health history
and keys it adds itself. Nothing is shared by accident: each account's data and keys live in their own files
(`workspaces/<id>/` next to the main database). The first account keeps the connectors and keys that existed before
accounts were introduced, and nobody inherits them if that account is removed. Connectors made in the web app cannot
point at this computer or a private network (`127.0.0.1`, `10.x`, `192.168.x`, `*.local` and similar are refused), so one
account cannot use Hermes to probe the others' services.

From the terminal (add `--user EMAIL` to act on one account's own connectors and keys):

```powershell
hermes auth set-password you@example.com   # create or change a password login (hidden prompt, 10+ characters)
hermes auth add you@gmail.com              # create an account in advance (also made on the first Google sign-in)
hermes auth list ; hermes auth remove you@example.com
hermes secret set GITHUB_TOKEN --user you@example.com
hermes run github_advisories --user you@example.com
```

Removing an account signs it out on its next click; its connectors and data stay on disk.

**Google sign-in (optional, recommended).** In the Google Cloud Console create an OAuth client of type *Web
application* and add the redirect URI `http://127.0.0.1:8000/auth/callback` (exactly that: Hermes sends people who
open `localhost:8000` to `127.0.0.1:8000` so the sign-in cookie and Google's redirect agree). Then store its two values:
`hermes secret set GOOGLE_CLIENT_ID` and `hermes secret set GOOGLE_CLIENT_SECRET`. Any Google account whose address
Google says is verified can sign in, and gets its own empty workspace. Hermes uses the authorization-code flow with PKCE
and keeps no Google tokens. These two values are app-wide and live in the main vault, which new accounts cannot reach.

Passwords are stored as salted scrypt hashes. Five wrong attempts lock that account (and your address) for ten minutes.
Every form carries a CSRF token, the session cookie is HttpOnly and SameSite=Lax, and sessions end after 8 hours.

## Adding a connector

1. Open `http://127.0.0.1:8000/connectors/new`.
2. Click a preset (GitHub advisories, NVD CVEs, or a public feed with no key) and edit it, or fill in the form.
   Each field is checked as you leave it, with the same rules as `hermes validate`.
3. Fields take the **name** of a stored secret, never a key. A pasted key is rejected and not echoed back.
4. Submit. A valid file is written to `config/connectors/` and starts running after the next `hermes serve`.

A source starting with `=` in a mapping row is a fixed value, for example `=high`.

**Prefer to write YAML?** Open the **Write YAML** tab on the same page. It holds a short template with four parts (about
the connector, how to log in, what to download, which fields to keep) and a plain-words comment on every line. Change the
example values to yours and press **Check**; your text is checked with the same rules as the form, errors show their line
number, and the file is saved exactly as you wrote it. The same template is available from the terminal: `hermes template`
prints it and `hermes template --out config/connectors/mine.yaml` writes it. Optional extras (several pages of results,
a health check, other logins) are in [docs/connector-options.md](docs/connector-options.md).

**Removing a connector.** Press **Remove** on its card, or run `hermes remove NAME`. The config moves to
`config/connectors/.trash/` (copy it back to restore), its health history, probes and cursor are cleared, and every record it fetched is
deleted too. A running `hermes serve` picks up added and removed connectors without a restart.
Adding a connector does the opposite: its first data is fetched about a second later and appears on the home page.

## Automatic recovery

Hermes fixes what it safely can, and never rewrites a config:

| Situation | What happens on its own |
|---|---|
| Server error, network failure, or rate limiting | Retries after 5, 15, then 45 minutes (the message on the card says so), then waits for the normal schedule |
| Connector paused by a rejected key | A probe runs hourly; if the key works again the connector resumes. Setting the secret again also resumes it |
| Records quarantined as `bad_data` | Re-tried after every good run; those that now map cleanly (for example after you fix the mapping) are saved and released |
| The same bad record on every run | Stored once, not once per run |
| A connector that has never run | Runs once a few seconds after `hermes serve` starts, so a new install is not empty until its next cron time |

Things only a person can fix (a wrong path, a changed API, a rejected key with no probe) stay stopped and say what to do.

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
