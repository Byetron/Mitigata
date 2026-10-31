# secintegrate

Config-driven security integration platform. Each source is one YAML file in `config/connectors/`;
no code changes are needed to add a source. See `PLATFORM_SPEC.md` for the full design.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
copy .env.example .env      # then fill in the values (the existing .env already has GITHUB_TOKEN and NVD_API_KEY)
```

## Use

```powershell
secintegrate validate                       # B2: path-specific errors, exit 1 on any problem
secintegrate run github_advisories --once   # one run now; prints pages, requests, records
secintegrate run nvd_cve --once
secintegrate run cisa_kev --once            # config-only 4th source (no auth)
secintegrate status                         # health table in the terminal
secintegrate serve                          # scheduler + web UI on http://localhost:8000
secintegrate db reset --yes
pytest
```

Web UI: `/health` (refreshes every 30 s) and `/connectors/new` (B5 form; it only accepts env var names).

## Before the first live run

- `github_members.yaml`: replace `YOUR_ORG_LOGIN` with an org your token belongs to.
- Jira connectors need `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` in `.env`. `validate` reports unset names.
  `serve` skips configs that fail schema validation and `run` refuses to start on an invalid config.
- `jira_issues` uses `/rest/api/3/search/jql` with cursor paging, because Atlassian retired `/rest/api/3/search`.
- The GitHub `updated=>=...` filter syntax should be confirmed with one `curl` (spec risk table).
- `incremental.cursor_format` and `lookback_minutes` are small additions to the spec's format, needed because
  JQL and NVD want non-ISO timestamps and JQL reads times in the account time zone.

## Secrets

Configs hold env var names only; `validate` rejects anything that looks like a real value. Secret values are
read at request time and registered with a redaction filter that scrubs logs, stored errors and quarantined
records. `.env`, `data/` and `logs/` are gitignored. Rotate any key that has been pasted into a chat.
