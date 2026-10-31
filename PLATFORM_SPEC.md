# Config-Driven Security Integration Platform: Build Spec

| Field | Value |
|---|---|
| Brief | PRD: Config-Driven Security Integration Platform (29 Oct 2026) |
| Sources | GitHub REST API, Jira Cloud REST API, NVD CVE API 2.0 |
| Bonus items | B1 Incremental sync, B2 Config validation, B5 Web form that generates config |
| Language | Python 3.11+ |
| Storage | SQLite (single file, `data/secintegrate.db`) |
| Secrets | Environment variables loaded from a local `.env` (never committed) |

---

## 1. Scope

### 1.1 Must-have requirements covered

| ID | Requirement | Where it is implemented |
|---|---|---|
| FR-1 | Auth: API key, Basic, Bearer, header key | `auth.py` (bearer, basic, api_key_header, none) |
| FR-2 | Endpoints: URL, method, query params | `runner.py`, config `endpoints[]` |
| FR-3 | Pagination: at least two styles | `pagination.py` (link_header, offset, page_number) |
| FR-4 | Schedule per connector | `scheduler.py` (cron expression per connector) |
| FR-5 | Mapping to common schema | `mapping.py`, `transforms.py` |
| FR-6 | Secrets never stored in plain text, logged or committed | `secrets.py`, `logging_utils.py` |
| FR-7 | Retries with backoff, 429 and 5xx handling | `http/retry.py`, `http/client.py` |
| FR-8 | Rate limits: slow down on 429, honour `Retry-After` | `http/ratelimit.py` |
| FR-9 | Bad records quarantined, run continues | `runner.py`, `quarantine` table |
| FR-10 | Health view per connection | `web/` health page and `secintegrate status` |
| FR-11 | Common schema storage with `source` and `fetched_at` | `storage/db.py` |

### 1.2 Bonus items chosen

| ID | Feature | Acceptance |
|---|---|---|
| B1 | Incremental sync | Second run fetches only records changed since the stored cursor. Verified by request count and URL parameters in logs. |
| B2 | Config validation before run | `secintegrate validate` exits non-zero with path-specific errors for any invalid config. `run` refuses to start on an invalid config. |
| B5 | Web form generates config | Form at `/connectors/new` produces a YAML file that passes B2 validation. Secret values are never accepted, only env var names. |

### 1.3 Out of scope

- Writing data back to any tool
- Alerts (B4) and threat detection logic
- OAuth2 flows (not needed; the three chosen sources use bearer, basic and header key)
- Paid API tiers

---

## 2. Source Analysis

### 2.1 Summary

| Source | Auth type | Paging style | Rate limit (with key) | Records used | Common schema target |
|---|---|---|---|---|---|
| GitHub REST: Security Advisories | Bearer token (`GITHUB_TOKEN`) | Link header, cursor-style (`after`) | 5,000 requests/hour (authenticated) | `GET /advisories` | Event |
| GitHub REST: Org members | Bearer token | Link header, page number | 5,000 requests/hour | `GET /orgs/{org}/members` | User |
| Jira Cloud: Users | Basic (email + API token) | Offset (`startAt`, `maxResults`) | Jira cost-based limits; respect `429` and `Retry-After` | `GET /rest/api/3/users/search` | User |
| Jira Cloud: Issues | Basic | Offset (`startAt`, `maxResults`) | Same as above | `GET /rest/api/3/search` | Event |
| NVD CVE API 2.0 | Header `apiKey` (`NVD_API_KEY`) | Offset (`startIndex`, `resultsPerPage`) | 50 requests per rolling 30 s with key; 5 without | `GET /rest/json/cves/2.0` | Event |

This gives three different login mechanisms (bearer, basic, header key) and three different paging mechanisms (link header, offset, and offset with a different parameter name). That satisfies FR-1 and FR-3 with margin.

### 2.2 GitHub: Security Advisories

- Endpoint: `GET https://api.github.com/advisories`
- Required headers: `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `Authorization: Bearer <token>`
- Paging: response carries `Link` header with `rel="next"`. Follow until no `next` link is present.
- Incremental filter: query parameter `updated` accepts a date comparison such as `updated=>=2026-01-01`. Verify the exact operator syntax against the current GitHub docs during the first run; this is the one place the spec relies on documented behaviour that may change.
- Useful record fields: `ghsa_id`, `cve_id`, `summary`, `severity`, `published_at`, `updated_at`.

### 2.3 GitHub: Organisation Members

- Endpoint: `GET https://api.github.com/orgs/{org}/members?per_page=100`
- Requires the token to belong to a member of the org. Use any org you belong to; use a personal org if no team org is available.
- Paging: `Link` header, `rel="next"`, page-number URLs.
- Useful record fields: `id`, `login`, `type`, `site_admin`.
- Known gap: the members list does not return email. Email is mapped to `null` and documented as such in the health view. This is a real limitation of the source, not a defect.

### 2.4 Jira Cloud: Users

- Endpoint: `GET {JIRA_BASE_URL}/rest/api/3/users/search?startAt=0&maxResults=50`
- Auth: `Authorization: Basic base64(JIRA_EMAIL:JIRA_API_TOKEN)`
- Paging: offset. Stop when a page returns an empty array.
- Useful record fields: `accountId`, `displayName`, `emailAddress`, `active`.
- Note: the response is a bare JSON array, so `records_path` is empty.

### 2.5 Jira Cloud: Issues

- Endpoint: `GET {JIRA_BASE_URL}/rest/api/3/search?jql=...&startAt=0&maxResults=50&fields=summary,issuetype,priority,created,updated`
- Response envelope: `{ "startAt", "maxResults", "total", "issues": [...] }`. Stop when `startAt + maxResults >= total`.
- Incremental filter: JQL `updated >= "{last_sync}" ORDER BY updated ASC`.
- Deprecation note: Atlassian is migrating search to `/rest/api/3/search/jql`, which uses token-based pagination (`nextPageToken`). The platform supports this through `pagination.type: cursor`. Check the current Atlassian changelog before the event, and switch the endpoint if the old route is removed on the account.
- Useful record fields: `key`, `fields.summary`, `fields.issuetype.name`, `fields.priority.name`, `fields.created`, `fields.updated`.

### 2.6 NVD CVE API 2.0

- Endpoint: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=0`
- Auth: header `apiKey: <NVD_API_KEY>`
- Paging: offset via `startIndex`, total via `totalResults`. Stop when `startIndex >= totalResults`.
- Incremental filter: `lastModStartDate` and `lastModEndDate`, ISO-8601 with milliseconds (for example `2026-01-01T00:00:00.000`). The API rejects date ranges wider than 120 days, so the runner splits the window into 120-day chunks.
- Response envelope: `{ "resultsPerPage", "startIndex", "totalResults", "vulnerabilities": [ { "cve": {...} } ] }`. `records_path` is `vulnerabilities`, and each record is wrapped in `cve`.
- Useful record fields: `cve.id`, `cve.published`, `cve.lastModified`, `cve.descriptions[0].value`, `cve.metrics.cvssMetricV31[0].cvssData.baseSeverity`.
- Missing CVSS v3.1 metrics are normal for older CVEs. The mapper must use the declared default rather than failing.

### 2.7 Credential Handling

The two keys you supplied go into a local `.env` file. The spec and all YAML configs reference only the variable names.

| Variable | Used by | Notes |
|---|---|---|
| `GITHUB_TOKEN` | GitHub connectors | Classic or fine-grained PAT. Fine-grained with read-only public access is sufficient. |
| `NVD_API_KEY` | NVD connector | UUID format, 36 characters |
| `JIRA_BASE_URL` | Jira connectors | `https://<site>.atlassian.net` |
| `JIRA_EMAIL` | Jira connectors | Account email |
| `JIRA_API_TOKEN` | Jira connectors | Created at id.atlassian.com under Security, API tokens |

Two keys have been pasted into a chat during planning. Rotate both before the event if they were shared on any public channel. Keys inside a `.env` file are safe as long as the file is gitignored (see section 4).

---

## 3. Configuration Format

Each connector is one YAML file in `config/connectors/`. The platform loads every file, validates it (B2), and schedules it (FR-4).

### 3.1 Top-level keys

| Key | Type | Required | Description |
|---|---|---|---|
| `connector` | string | yes | Unique id. Lowercase letters, digits, underscores. Used as the primary key in `connections`. |
| `source` | string | yes | Label stored in every record's `source` field. |
| `enabled` | bool | no (default `true`) | Disabled connectors are validated but never scheduled. |
| `schedule` | string | yes | Five-field cron expression, e.g. `*/15 * * * *`. |
| `base_url` | string | yes | Supports `${ENV_VAR}` substitution. |
| `auth` | object | yes | See 3.2. |
| `headers` | map | no | Static headers added to every request. |
| `rate_limit` | object | no | `{ max_requests, per_seconds }`. Client-side throttle applied before sending. |
| `retry` | object | no | Overrides the defaults in section 5.3. |
| `endpoints` | list | yes | One or more endpoints. Each is pulled in order on each run. |

### 3.2 Auth block

| `type` | Required fields | Behaviour |
|---|---|---|
| `bearer` | `secret` | Sends `Authorization: Bearer <value>` |
| `basic` | `username_env`, `secret` | Sends `Authorization: Basic base64(username:value)` |
| `api_key_header` | `header`, `secret` | Sends `<header>: <value>` |
| `none` | none | No credentials sent |

`secret` is an environment variable name, never a value. The validator rejects any `secret` value that does not match `^[A-Z][A-Z0-9_]*$`. This is the mechanism behind FR-6: a real key pasted into YAML fails validation.

### 3.3 Endpoint block

| Key | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique within the connector |
| `method` | `GET` or `POST` | no (default `GET`) | |
| `path` | string | yes | Appended to `base_url`. May contain `{var}` placeholders filled from `vars`. |
| `vars` | map | no | Values for path placeholders, e.g. `org: my-org` |
| `params` | map | no | Query parameters |
| `records_path` | string | no | Dot path to the list of records in the response. Empty means the response is the list. |
| `pagination` | object | no | See 3.4. Omit for single-request endpoints. |
| `incremental` | object | no | See 3.5. Enables B1. |
| `mapping` | object | yes | See 3.6 |

### 3.4 Pagination block

| `type` | Fields | Stop condition |
|---|---|---|
| `link_header` | `rel` (default `next`) | No `rel` link in the `Link` header |
| `offset` | `start_param`, `limit_param`, `limit`, `total_path` (optional) | `total_path` reached, or empty page when `total_path` absent |
| `page_number` | `param`, `start` (default 1), `stop_when_empty` | Empty page |
| `cursor` | `param`, `next_path` | `next_path` is null or absent |

Field mapping per connector:

| Connector | Pagination block |
|---|---|
| GitHub advisories | `link_header`, `rel: next` |
| GitHub members | `link_header`, `rel: next` |
| Jira users | `offset`, `start_param: startAt`, `limit_param: maxResults`, `limit: 50` |
| Jira issues | `offset`, `start_param: startAt`, `limit_param: maxResults`, `limit: 50`, `total_path: total` |
| NVD | `offset`, `start_param: startIndex`, `limit_param: resultsPerPage`, `limit: 2000`, `total_path: totalResults` |

### 3.5 Incremental block (B1)

| Key | Description |
|---|---|
| `cursor_field` | Dot path in each record that holds the change timestamp |
| `param` | Query parameter to set. Used for GitHub and Jira. |
| `format` | Template for the parameter value. `{value}` is replaced with the stored cursor. |
| `initial` | Cursor used on the first run, before any state exists |
| `start_param`, `end_param`, `window_days` | Used instead of `param` for NVD date-window splitting |

The stored cursor is the maximum `cursor_field` value seen in a fully successful run. A failed run does not advance the cursor, so the next run re-fetches the same window. Writes are upserts keyed by `(source, id)`, so re-fetching is safe.

### 3.6 Mapping block

Each target field is either a source-field rule or a constant.

```yaml
mapping:
  target: user            # user | device | event
  fields:
    id:        { from: id, transform: to_string, required: true }
    name:      { from: login, default: "" }
    email:     { from: email, default: null }
    status:    { const: active }
    last_login: { default: null }
```

Rule keys:

| Key | Meaning |
|---|---|
| `from` | Dot path with optional `[index]`, e.g. `cve.descriptions[0].value` |
| `const` | Fixed value |
| `default` | Used when `from` is missing or null. Without `default`, a missing value fails the record. |
| `required` | When `true`, a missing value quarantines the record even if `default` is set |
| `transform` | One of the transforms in 3.7 |

`source` and `fetched_at` are added by the runner for every record, so they never appear in mapping blocks.

### 3.7 Transforms

| Name | Input | Output |
|---|---|---|
| `to_string` | any scalar | string |
| `lower` / `upper` | string | string |
| `strip` | string | string |
| `iso8601` | ISO-8601 string with or without offset | UTC ISO-8601 string with `Z` suffix |
| `epoch_ms_to_iso` | integer milliseconds | UTC ISO-8601 string |
| `active_to_status` | bool | `"active"` if true, else `"disabled"` |

A transform that raises an exception fails that record and sends it to quarantine. It never fails the run.

### 3.8 Full example: GitHub Security Advisories (Event target)

```yaml
connector: github_advisories
source: github
enabled: true
schedule: "*/15 * * * *"
base_url: https://api.github.com
auth:
  type: bearer
  secret: GITHUB_TOKEN
headers:
  Accept: application/vnd.github+json
  X-GitHub-Api-Version: "2022-11-28"
rate_limit:
  max_requests: 4000
  per_seconds: 3600
endpoints:
  - name: advisories
    method: GET
    path: /advisories
    params:
      per_page: 100
    records_path: ""
    pagination:
      type: link_header
      rel: next
    incremental:
      cursor_field: updated_at
      param: updated
      format: ">={value}"
      initial: "2026-01-01"
    mapping:
      target: event
      fields:
        id:          { from: ghsa_id, required: true }
        type:        { const: advisory }
        severity:    { from: severity, transform: lower, default: unknown }
        timestamp:   { from: published_at, transform: iso8601, required: true }
        description: { from: summary, default: "" }
```

### 3.9 Full example: GitHub Org Members (User target)

```yaml
connector: github_members
source: github
enabled: true
schedule: "0 * * * *"
base_url: https://api.github.com
auth:
  type: bearer
  secret: GITHUB_TOKEN
headers:
  Accept: application/vnd.github+json
  X-GitHub-Api-Version: "2022-11-28"
endpoints:
  - name: members
    method: GET
    path: /orgs/{org}/members
    vars:
      org: YOUR_ORG_LOGIN
    params:
      per_page: 100
    records_path: ""
    pagination:
      type: link_header
      rel: next
    mapping:
      target: user
      fields:
        id:         { from: login, required: true }
        name:       { from: login, default: "" }
        email:      { const: null }
        status:     { const: active }
        last_login: { const: null }
```

Note: `id` uses `login` here so that the user id is human-readable. Keep the same choice across connectors if you change it, because `(source, id)` is the uniqueness key.

### 3.10 Full example: Jira Cloud Users (User target)

```yaml
connector: jira_users
source: jira
enabled: true
schedule: "30 * * * *"
base_url: ${JIRA_BASE_URL}
auth:
  type: basic
  username_env: JIRA_EMAIL
  secret: JIRA_API_TOKEN
headers:
  Accept: application/json
endpoints:
  - name: users
    method: GET
    path: /rest/api/3/users/search
    params:
      maxResults: 50
    records_path: ""
    pagination:
      type: offset
      start_param: startAt
      limit_param: maxResults
      limit: 50
    mapping:
      target: user
      fields:
        id:         { from: accountId, required: true }
        name:       { from: displayName, default: "" }
        email:      { from: emailAddress, default: null }
        status:     { from: active, transform: active_to_status, default: disabled }
        last_login: { const: null }
```

### 3.11 Full example: Jira Cloud Issues (Event target, B1)

```yaml
connector: jira_issues
source: jira
enabled: true
schedule: "*/30 * * * *"
base_url: ${JIRA_BASE_URL}
auth:
  type: basic
  username_env: JIRA_EMAIL
  secret: JIRA_API_TOKEN
headers:
  Accept: application/json
endpoints:
  - name: issues
    method: GET
    path: /rest/api/3/search
    params:
      maxResults: 50
      fields: "summary,issuetype,priority,created,updated"
    records_path: issues
    pagination:
      type: offset
      start_param: startAt
      limit_param: maxResults
      limit: 50
      total_path: total
    incremental:
      cursor_field: fields.updated
      param: jql
      format: 'updated >= "{value}" ORDER BY updated ASC'
      initial: "2026-01-01 00:00"
    mapping:
      target: event
      fields:
        id:          { from: key, required: true }
        type:        { from: fields.issuetype.name, default: task }
        severity:    { from: fields.priority.name, transform: lower, default: unknown }
        timestamp:   { from: fields.created, transform: iso8601, required: true }
        description: { from: fields.summary, default: "" }
```

### 3.12 Full example: NVD CVE API (Event target, B1 with date windows)

```yaml
connector: nvd_cve
source: nvd
enabled: true
schedule: "0 */2 * * *"
base_url: https://services.nvd.nist.gov
auth:
  type: api_key_header
  header: apiKey
  secret: NVD_API_KEY
rate_limit:
  max_requests: 45
  per_seconds: 30
endpoints:
  - name: cves
    method: GET
    path: /rest/json/cves/2.0
    params:
      resultsPerPage: 2000
    records_path: vulnerabilities
    pagination:
      type: offset
      start_param: startIndex
      limit_param: resultsPerPage
      limit: 2000
      total_path: totalResults
    incremental:
      cursor_field: cve.lastModified
      start_param: lastModStartDate
      end_param: lastModEndDate
      window_days: 120
      initial: "2026-01-01T00:00:00.000"
    mapping:
      target: event
      fields:
        id:          { from: cve.id, required: true }
        type:        { const: cve }
        severity:    { from: cve.metrics.cvssMetricV31[0].cvssData.baseSeverity, transform: lower, default: unknown }
        timestamp:   { from: cve.published, transform: iso8601, required: true }
        description: { from: cve.descriptions[0].value, default: "" }
```

The `rate_limit` is set to 45 per 30 seconds, not 50, to leave headroom for clock skew. The NVD server counts requests in a rolling window, so the client-side throttle needs to be slightly under the published limit.

---

## 4. Repository Layout

```
sec-integrate/
├── pyproject.toml
├── .env                      # local secrets, GITIGNORED
├── .env.example              # placeholder names only, committed
├── .gitignore                # must include .env, data/, *.db, logs/
├── README.md
├── config/
│   └── connectors/
│       ├── github_advisories.yaml
│       ├── github_members.yaml
│       ├── jira_users.yaml
│       ├── jira_issues.yaml
│       ├── nvd_cve.yaml
│       └── cisa_kev.yaml     # 4th source, added to prove "config only" (section 9)
├── data/
│   └── secintegrate.db       # created at runtime, GITIGNORED
├── src/secintegrate/
│   ├── __init__.py
│   ├── cli.py                # typer commands
│   ├── config/
│   │   ├── schema.py         # pydantic models for the YAML format
│   │   ├── loader.py         # reads files, substitutes ${ENV}
│   │   └── validator.py      # B2: produces path-specific errors
│   ├── secrets.py            # resolves env var names, registers values for redaction
│   ├── logging_utils.py      # redaction filter
│   ├── http/
│   │   ├── client.py         # httpx wrapper: headers, auth, throttle, retry
│   │   ├── retry.py          # backoff policy
│   │   └── ratelimit.py      # token bucket, max_requests per window
│   ├── auth.py               # bearer, basic, api_key_header, none
│   ├── pagination.py         # link_header, offset, page_number, cursor
│   ├── mapping.py            # dot-path resolution, rules, quarantine decisions
│   ├── transforms.py         # transform registry
│   ├── incremental.py        # cursor state and NVD date windows (B1)
│   ├── runner.py             # executes one connector run end to end
│   ├── scheduler.py          # APScheduler wrapper
│   ├── storage/
│   │   ├── schema.sql
│   │   └── db.py             # upserts, runs, quarantine, sync_state
│   └── web/
│       ├── app.py            # Flask app: /health, /connectors/new (B5)
│       ├── forms.py          # form-to-config builder
│       └── templates/
│           ├── health.html
│           └── new_connector.html
└── tests/
    ├── fixtures/             # recorded responses for each source
    ├── test_validator.py
    ├── test_pagination.py
    ├── test_mapping.py
    ├── test_retry.py
    ├── test_incremental.py
    └── test_failures.py      # section 8
```

### 4.1 `.gitignore` (required lines)

```
.env
data/
*.db
logs/
__pycache__/
```

### 4.2 Libraries

| Purpose | Library | Reason |
|---|---|---|
| HTTP | `httpx` | Sync and async, timeouts, clean API |
| Config models | `pydantic` v2 | Field-level errors for B2 |
| YAML | `PyYAML` | Standard |
| Env loading | `python-dotenv` | Reads `.env` |
| CLI | `typer` | Subcommands with little code |
| Scheduling | `APScheduler` | Cron triggers |
| Web | `Flask` | Smallest server for the health page and form |
| Tests | `pytest`, `pytest-httpserver` | Mock the APIs locally to inject failures |

Retries are hand-written in `http/retry.py` rather than using a retry library. The brief is assessed on understanding the policy, so the policy should be visible in code.

---

## 5. Runtime Behaviour

### 5.1 Run lifecycle

For each connector run:

1. Load config, resolve `${ENV}` in `base_url`, check secrets exist (names only in logs).
2. Create a row in `runs` with status `running`.
3. Read `sync_state` for the connector's endpoints to get the incremental cursor.
4. For each endpoint:
   1. Build the initial request from `path`, `vars`, `params`, and the incremental filter.
   2. Send the request through the client (throttle, retry, auth).
   3. Extract records from `records_path`.
   4. Map each record. Failures go to `quarantine`. Successes are upserted into the common table.
   5. Follow pagination until the stop condition.
   6. Commit after each page so a crash keeps progress for that page.
5. If every endpoint completed without a fatal error, advance the cursor to the maximum `cursor_field` seen, and set run status to `success` (or `partial` if any record was quarantined).
6. If a fatal error occurred, set status to `failed`, do not advance the cursor, and store the error.
7. Update the `connections` health row.

### 5.2 Status values

| Run status | Meaning |
|---|---|
| `success` | All records mapped, cursor advanced |
| `partial` | Run completed, one or more records quarantined, cursor advanced |
| `failed` | Fatal error (auth, network after retries, config), cursor not advanced |

### 5.3 Retry policy (FR-7)

| Condition | Action |
|---|---|
| Connection error, timeout, HTTP 500, 502, 503, 504 | Retry with waits of 1 s, 2 s, 4 s. Maximum 3 retries. Then fail the run. |
| HTTP 429 | Wait `Retry-After` seconds (default 30 s if the header is absent). Maximum 5 waits per request. Does not consume the exponential budget. |
| HTTP 401, 403 | Fail immediately with `auth_failed`. No retry. |
| HTTP 404 | Fail immediately with `not_found`. Usually a wrong path. |
| Other 4xx | Fail immediately with `client_error`. |
| Malformed JSON in a 200 response | Fail the run with `bad_response`. |

The connector-level `retry` block can override `max_retries`, `backoff_seconds` (list), and `retry_after_default`.

### 5.4 Rate limiting (FR-8)

Client-side token bucket per connector, configured by `rate_limit`. It runs before each request. It is independent of server responses. Server responses still win: a 429 response overrides the bucket and triggers the `Retry-After` wait above.

### 5.5 Secrets (FR-6)

- Config refers to `GITHUB_TOKEN`. The runner reads the value from `os.environ` at request time.
- The secret value is registered with the redaction filter at startup. Any log line containing the value is rewritten with `***`.
- `Authorization` and any header named `apiKey` are always redacted in debug logs.
- Error messages say `auth_failed for github_advisories (env GITHUB_TOKEN)`. They never include the value.
- `.env` is gitignored. `.env.example` lists names with empty values.

### 5.6 Bad data (FR-9)

Quarantine row written when:
- A `required: true` field is missing or null.
- A transform raises an exception.
- A record is not an object.

Quarantine table stores the connector, endpoint, record index, the error reason, and the raw record JSON. The run continues.

Run summary example: `jira_users: 3 of 500 records invalid, quarantined. Status: partial.`

---

## 6. Storage

### 6.1 Schema (`storage/schema.sql`)

```sql
CREATE TABLE IF NOT EXISTS users (
  source      TEXT NOT NULL,
  id          TEXT NOT NULL,
  name        TEXT,
  email       TEXT,
  status      TEXT,
  last_login  TEXT,
  fetched_at  TEXT NOT NULL,
  PRIMARY KEY (source, id)
);

CREATE TABLE IF NOT EXISTS devices (
  source      TEXT NOT NULL,
  id          TEXT NOT NULL,
  hostname    TEXT,
  ip          TEXT,
  os          TEXT,
  owner       TEXT,
  last_seen   TEXT,
  fetched_at  TEXT NOT NULL,
  PRIMARY KEY (source, id)
);

CREATE TABLE IF NOT EXISTS events (
  source      TEXT NOT NULL,
  id          TEXT NOT NULL,
  type        TEXT,
  severity    TEXT,
  timestamp   TEXT,
  description TEXT,
  fetched_at  TEXT NOT NULL,
  PRIMARY KEY (source, id)
);

CREATE TABLE IF NOT EXISTS connections (
  connector            TEXT PRIMARY KEY,
  status               TEXT NOT NULL,        -- healthy | degraded | failing | never_run
  last_run_started_at  TEXT,
  last_run_finished_at TEXT,
  last_records_pulled  INTEGER DEFAULT 0,
  last_error           TEXT,
  consecutive_failures INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connector     TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  status        TEXT NOT NULL,              -- running | success | partial | failed
  records_ok    INTEGER DEFAULT 0,
  records_bad   INTEGER DEFAULT 0,
  error         TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id       INTEGER NOT NULL,
  connector    TEXT NOT NULL,
  endpoint     TEXT NOT NULL,
  record_index INTEGER,
  reason       TEXT NOT NULL,
  raw_json     TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_state (
  connector   TEXT NOT NULL,
  endpoint    TEXT NOT NULL,
  cursor      TEXT,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (connector, endpoint)
);
```

### 6.2 Routing rule

`mapping.target` decides the table: `user` goes to `users`, `device` to `devices`, `event` to `events`. Every row includes `source` and `fetched_at`, which the runner sets. This satisfies FR-11.

### 6.3 Upsert behaviour

`INSERT ... ON CONFLICT(source, id) DO UPDATE SET ...`. A re-fetched record overwrites the old values, so repeated runs are idempotent.

---

## 7. Interfaces

### 7.1 CLI

| Command | Behaviour |
|---|---|
| `secintegrate validate [PATH]` | Validates all connector files (B2). Exit 0 if all valid, 1 otherwise. Prints `file:line field: message`. Checks that each referenced env var is set, but never prints its value. |
| `secintegrate run CONNECTOR [--once] [--no-throttle]` | Runs one connector now. `--no-throttle` disables the client-side bucket, used to trigger 429 in tests. |
| `secintegrate serve [--port 8000]` | Starts the scheduler and the web server. |
| `secintegrate status` | Prints the health table in the terminal. |
| `secintegrate db reset` | Drops and recreates tables. Asks for confirmation. |

### 7.2 Validator rules (B2)

| Rule | Example failure message |
|---|---|
| Schema types match | `endpoints[0].limit: expected integer, got "fifty"` |
| `secret` is an env var name | `auth.secret: looks like a real value. Use an env var name such as GITHUB_TOKEN` |
| Env var exists | `auth.secret: GITHUB_TOKEN is not set in .env` (name only) |
| `schedule` is valid cron | `schedule: "*/15 * *" has 4 fields, expected 5` |
| `connector` is unique across files | `connector github_members is defined in two files` |
| Pagination fields match type | `pagination.type=offset requires start_param and limit_param` |
| Incremental fields match type | `incremental.param and start_param/end_param are mutually exclusive` |
| Mapping target is valid | `mapping.target: must be one of user, device, event` |
| Target required fields present | `mapping.target=user requires id and name` |
| Transform name is known | `transform: "lowr" is not a known transform. Did you mean lower?` |

### 7.3 Health page (FR-10)

Route: `GET /health`. Refreshes every 30 seconds.

| Column | Source |
|---|---|
| Connector | `connections.connector` |
| Status | `connections.status` (green healthy, amber degraded, red failing, grey never run) |
| Last run | `connections.last_run_finished_at` |
| Records pulled | `connections.last_records_pulled` |
| Quarantined in last run | Count from `runs.records_bad` |
| Last error | `connections.last_error` (redacted) |
| Consecutive failures | `connections.consecutive_failures` |

Status rules:
- `healthy`: last run `success`
- `degraded`: last run `partial`
- `failing`: last run `failed` and `consecutive_failures >= 3`, or last run `failed` with `auth_failed`
- `never_run`: no row in `runs`

### 7.4 Web form for new connectors (B5)

Route: `GET /connectors/new` renders the form. `POST /connectors/new` builds the YAML, validates it with the same code as `secintegrate validate`, and writes the file if valid.

Form fields:

| Field | Input type | Validation |
|---|---|---|
| Connector id | text | Lowercase, digits, underscores, unique |
| Source label | text | Non-empty |
| Base URL | text | Must start with `https://` |
| Auth type | select | bearer, basic, api_key_header, none |
| Secret env var name | text | `^[A-Z][A-Z0-9_]*$`. The form has no field for a secret value. |
| Username env var (basic only) | text | Same pattern as above |
| Header name (api_key_header only) | text | Valid HTTP header token |
| Endpoint path | text | Starts with `/` |
| Pagination type | select | none, link_header, offset, page_number |
| Pagination parameters | conditional text fields | Depend on type |
| Schedule | text | Valid cron |
| Mapping rows | repeatable: target field, source path, transform, required | Target field must be valid for the chosen target |

On success the page shows the generated YAML, the file path, and a link to `/health`. On failure it re-renders the form with the validator's messages next to each field.

---

## 8. Test Plan

### 8.1 Failure scenarios (from brief section 3)

| Scenario | How to trigger | Expected behaviour |
|---|---|---|
| Wrong or expired key | Set `GITHUB_TOKEN=invalid` and run `github_advisories` | Status `failed`, error `auth_failed`, one request sent (no retries), key value absent from logs and DB |
| Network loss mid-run | Disable network after the first page, or point `base_url` at a closed port after page 1 via `pytest-httpserver` | Retries at 1 s, 2 s, 4 s, then status `failed`. Cursor not advanced. Page 1 records remain in the DB. |
| Rate limit (429) | `nvd_cve` with `--no-throttle` and a key set to 5 per 30 s, or a local mock returning 429 with `Retry-After: 3` | Run waits the `Retry-After` interval and continues. Final status `success`. Request log shows spacing of at least the header value. |
| Record with missing fields | Mock a GitHub advisory without `ghsa_id` | Record appears in `quarantine` with reason `required field missing: ghsa_id`. Run status `partial`. `records_bad` = 1. |
| Malformed record type | Mock a Jira user that is a string rather than an object | Quarantined, run continues |
| Server 500 then success | Mock returns 500 twice then 200 | Run succeeds on the third attempt |

### 8.2 Unit tests

| Module | Tests |
|---|---|
| `validator` | One invalid fixture per rule in section 7.2, asserting the exact error path |
| `pagination` | Link header parsing with and without `rel="next"`; offset stop at `total`; page-number stop on empty page |
| `mapping` | Dot path with index, missing value with default, required missing, transform errors |
| `retry` | Backoff sequence 1, 2, 4; `Retry-After` honoured; 401 never retried |
| `incremental` | NVD 120-day window split for a 300-day range yields 3 windows; Jira JQL formatting; cursor advances only on success |
| `redaction` | Secret value never appears in captured log output |

### 8.3 Live tests

Run `secintegrate run <connector> --once` against each real source and record:
- records pulled
- pages fetched
- wall-clock time
- status

Save the output in `docs/live-run-log.md` as evidence for FR-"Proven".

---

## 9. Acceptance Criteria

| # | Criterion | How it is shown |
|---|---|---|
| A1 | Three real sources connected, differing in auth and paging | Live run log for GitHub (bearer, link header), Jira (basic, offset), NVD (header key, offset) |
| A2 | New source added by config only | Add `cisa_kev.yaml` (no auth, JSON feed) with no code change. Validate, run, and show records in `events`. Record the time taken; target under 60 minutes. |
| A3 | Every connector fails the same way | Section 8.1 scenarios produce identical status and error vocabulary across all three connectors |
| A4 | Secrets never in config, logs or Git | `grep -r "ghp_\|<first-chars-of-your-NVD-key>" .` returns matches only in `.env`. `git check-ignore .env` returns `.env`. |
| A5 | Health visible | Screenshot of `/health` showing all connectors with status |
| A6 | Bonus B1 demonstrated | Second run of `github_advisories` requests `updated=>=<last cursor>` and fetches fewer records than the first run |
| A7 | Bonus B2 demonstrated | `secintegrate validate` on a deliberately broken config prints the expected messages and exits 1 |
| A8 | Bonus B5 demonstrated | Form submission creates a valid YAML file that passes `validate` |

---

## 10. Build Plan

| Block | Tasks | Done when |
|---|---|---|
| 1. Core runner | Config loader, schema, auth, GET with pagination, mapping, SQLite upsert | `github_advisories` runs end to end once |
| 2. Reliability | Retry policy, 429 handling, throttle, quarantine, redaction | Section 8.1 scenarios pass |
| 3. Sources | `github_members`, `jira_users`, `jira_issues`, `nvd_cve` configs | All four pulled into `users` and `events` |
| 4. Bonus | B2 validator and CLI, B1 incremental state, B5 form | A7, A6, A8 pass |
| 5. Health and proof | `/health` page, live run log, `cisa_kev.yaml` config-only demo, README | A1, A2, A5 pass |
| 6. Polish | Tests green, secret scan clean, demo script | A4 passes |

---

## 11. Known Risks

| Risk | Mitigation |
|---|---|
| GitHub advisories `updated` operator syntax differs from the documented form | Test the filter once with `curl` before coding. Fall back to a full pull with client-side filtering on `updated_at`. |
| Jira `/rest/api/3/search` removed or restricted on the account | Switch the endpoint to `/rest/api/3/search/jql` and set `pagination.type: cursor` with `next_path: nextPageToken`. The platform already supports the cursor type. |
| NVD returns 403 or 503 under load | Retry policy handles 503. Lower `rate_limit` if 429 appears more than twice per run. |
| Jira user search requires admin permission | Use `GET /rest/api/3/myself` as a single-user fallback. Document the reduced scope. |
| GitHub members endpoint returns 404 for personal accounts | Use an org you belong to. Create a free org if needed. |
| Shared keys exposed in chat history | Rotate before submission. Update `.env` only; no YAML changes are needed. |

---

## 12. Environment Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install httpx pydantic pyyaml python-dotenv typer apscheduler flask pytest pytest-httpserver
cp .env.example .env               # then fill in JIRA_* values
secintegrate validate
secintegrate run github_advisories --once
secintegrate run nvd_cve --once
secintegrate run jira_issues --once
secintegrate serve
```

Open `http://localhost:8000/health` to see the connections.
