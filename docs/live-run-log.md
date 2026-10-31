# Live run log

Evidence for spec section 8.3 and acceptance criteria A1, A2, A6. Every number below came from a real
`hermes run <connector> --once` against the live service on **31 October 2026 (UTC)**, with API keys read from the
encrypted vault. Nothing here was mocked.

## Results

| Connector | Source | Auth | Paging | Records | Pages | Requests | Time | Status |
|---|---|---|---|---|---|---|---|---|
| `cisa_kev` | CISA Known Exploited Vulnerabilities | none | single request | 1,766 | 1 | 1 | 0.5 s | success |
| `epss_high_risk` | FIRST EPSS (score above 0.9) | none | offset (`offset`/`limit`, total in `total`) | 828 | 9 | 9 | 6.8 s | success |
| `hibp_breaches` | Have I Been Pwned breach list | none | single request | 1,048 | 1 | 1 | 1.9 s | success |
| `feodo_c2` | abuse.ch Feodo botnet C2 IPs | none | single request | 5 (devices) | 1 | 1 | 0.4 s | success |
| `github_advisories` (first run) | GitHub Security Advisories | bearer token | link header | 2,377 | 24 | 24 | 19.6 s | success |
| `github_advisories` (second run) | same | bearer token | link header | **6** | 1 | 1 | 0.9 s | success |
| `nvd_cve` | NIST NVD CVE API 2.0 | API key header | offset (`startIndex`/`resultsPerPage`, total in `totalResults`) | 3,185 | 2 | 2 | 6.4 s | success |

After these runs `hermes status` showed all six connectors **healthy**, none quarantined, and the database held
9,204 events (CISA 1,766, FIRST EPSS 828, GitHub 2,377, Have I Been Pwned 1,048, NVD 3,185) and 5 devices.

## What this proves

- **A1, three real sources with different login and paging.** GitHub uses a bearer token and `Link` header paging.
  NVD uses an API key sent in the `apiKey` header with offset paging. EPSS uses offset paging with no login. Three more
  sources need no key at all.
- **A2, a new source by configuration only.** `cisa_kev`, `epss_high_risk`, `hibp_breaches` and `feodo_c2` were each added
  as one YAML file with no code change.
- **A6, incremental sync.** The second `github_advisories` run asked only for advisories updated since the saved cursor and
  fetched **6 records instead of 2,377**, in 1 request instead of 24.
- **Secrets.** GitHub and NVD keys were read from the AES-256-GCM vault at request time. No key appears in this log, in
  the configs, or on the dashboard.

## Notes

- Jira is not part of this project. It was removed on request, so the spec's Jira rows do not apply.
- `github_members` was also removed, so there is no org-members run.
- The failure paths (401, 404, 422, 429, 500, bad JSON, changed schema, one bad record, no network) were exercised
  against a local test server rather than a live provider, and are covered by `tests/test_failures.py`.
- Times are wall-clock for one run from a home connection and will vary.
