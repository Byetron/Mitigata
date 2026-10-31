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
  status               TEXT NOT NULL,
  last_run_started_at  TEXT,
  last_run_finished_at TEXT,
  last_records_pulled  INTEGER DEFAULT 0,
  last_error           TEXT,
  consecutive_failures INTEGER DEFAULT 0,
  paused               INTEGER DEFAULT 0,
  last_category        TEXT,
  message              TEXT
);

CREATE TABLE IF NOT EXISTS runs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connector     TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  status        TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS probes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  connector   TEXT NOT NULL,
  checked_at  TEXT NOT NULL,
  ok          INTEGER NOT NULL,
  category    TEXT,
  http_status INTEGER,
  latency_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_probes_connector ON probes (connector, id);

CREATE TABLE IF NOT EXISTS app_users (
  email         TEXT PRIMARY KEY,
  password_hash TEXT,
  added_at      TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS app_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
