# secintegrate

Config-driven security integration platform. Each source is one YAML file in `config/connectors/`;
no code changes are needed to add a source. See `PLATFORM_SPEC.md` for the full design.

## Connectors

| Connector | Source | Auth | Paging | Lands in |
|---|---|---|---|---|
| `github_advisories` | GitHub Security Advisories | bearer token | link header | events |
| `nvd_cve` | NIST NVD CVE API 2.0 | API key header | offset | events |
| `cisa_kev` | CISA Known Exploited Vulnerabilities | none | single request | events |
| `epss_high_risk` | FIRST EPSS (score above 0.9) | none | offset | events |
| `hibp_breaches` | Have I Been Pwned breach list | none | single request | events |
| `feodo_c2` | abuse.ch Feodo botnet C2 IPs | none | single request | devices |

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

Web UI: `/` is the home dashboard with connector health (refreshes every 30 s) and `/connectors/new` is the
B5 form (it only accepts env var names). `/health` redirects to `/`.

## Before the first live run

- `validate` reports unset env var names. `serve` skips configs that fail schema validation and `run`
  refuses to start on an invalid config.
- Keyless connectors (`cisa_kev`, `feodo_c2`, `epss_high_risk`, `hibp_breaches`) work with no setup.
- The GitHub `updated=>=...` filter syntax should be confirmed with one `curl` (spec risk table).
- `incremental.cursor_format` and `lookback_minutes` are small additions to the spec's format, needed because
  NVD wants non-ISO timestamps.

## Secrets

Configs hold env var names only; `validate` rejects anything that looks like a real value. Secret values are
read at request time and registered with a redaction filter that scrubs logs, stored errors and quarantined
records. `.env`, `data/` and `logs/` are gitignored. Rotate any key that has been pasted into a chat.
