# Connector options

The starter template (`hermes template`) is all most connectors need. This page lists the extras, each one small.
Add them under the connector in the same YAML file, then run `hermes validate`.

## The service gives results in several pages

Add `pagination` under the endpoint. Pick the style your service uses.

```yaml
    pagination:
      type: link_header          # the reply says where the next page is (GitHub does this)
```
```yaml
    pagination:
      type: offset               # you ask for "items 0 to 99", then "100 to 199"
      start_param: offset        # the name of the "where to start" setting in the address
      limit_param: limit         # the name of the "how many" setting
      limit: 100
      total_path: total          # where the total count is in the reply (optional)
```
```yaml
    pagination:
      type: page_number          # you ask for page 1, then page 2
      param: page
```
```yaml
    pagination:
      type: cursor               # each reply gives a token for the next one
      param: after               # the setting that carries the token
      next_path: next_token      # where the token is in the reply
```

Hermes stops by itself if a service keeps repeating the same page. The safety limit is 1000 pages, and you can change it
with `max_pages: 200`.

## Only fetch what changed

```yaml
    incremental:
      cursor_field: updated_at   # the field in each record that holds its change time
      param: updated_since       # the setting that asks for "changed since"
      initial: "2026-01-01"      # where to start the first time
```

## Check the connection between runs (recommended)

```yaml
probe:
  path: /health                  # one cheap request. Pick something quick that needs the same login
  interval_minutes: 15
```

## Other logins

| You need | Use |
|---|---|
| A token sent as `Authorization: Bearer ...` | `type: bearer`, `secret: NAME` |
| Username and password | `type: basic`, `username_env: USER_NAME`, `secret: PASSWORD_NAME` |
| A key in a custom header | `type: api_key_header`, `header: X-Api-Key`, `secret: NAME` |
| No login | `type: none` |

`secret`, `username_env` and `header` values are the **names** of keys stored with `hermes secret set`, except `header`,
which is the header's own name.

## Extra headers, and slowing down

```yaml
headers:
  Accept: application/json
rate_limit:                      # never send more than 45 requests every 30 seconds
  max_requests: 45
  per_seconds: 30
```

## Fields and changes you can make to values

Each line under `fields:` is one of these:

| Write | Meaning |
|---|---|
| `{ from: name, required: true }` | take this field. If it is missing, set the record aside |
| `{ from: name, default: unknown }` | take this field, or use `unknown` if it is missing |
| `{ const: high }` | always use this fixed value |
| `{ from: name, transform: lower }` | change the value. Choices: `to_string`, `lower`, `upper`, `strip`, `iso8601`, `epoch_ms_to_iso`, `active_to_status` |

A field is either `required: true` or has a `default`, not both. An `event` needs `id`, `timestamp` and `severity`.
A `user` needs `id` and `name`. A `device` needs `id`. To reach inside a reply, join names with dots and use `[0]` for
the first item of a list: `cve.descriptions[0].value`.
