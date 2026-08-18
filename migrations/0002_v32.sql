PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS workspace_settings (
  workspace_id TEXT PRIMARY KEY,
  retry_policy_json TEXT NOT NULL DEFAULT '{}',
  alert_policy_json TEXT NOT NULL DEFAULT '{}',
  ui_prefs_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS site_profiles (
  workspace_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  family TEXT NOT NULL,
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  last_probe_at TEXT,
  probe_errors_json TEXT NOT NULL DEFAULT '[]',
  probe_meta_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, site_id)
);
CREATE INDEX IF NOT EXISTS idx_site_profiles_workspace ON site_profiles(workspace_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL,
  site_id TEXT,
  level TEXT NOT NULL,
  rule_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  title TEXT NOT NULL,
  detail TEXT,
  metric_value REAL,
  threshold_value REAL,
  sample_size INTEGER,
  first_triggered_at TEXT NOT NULL,
  last_triggered_at TEXT NOT NULL,
  acked_at TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_events_workspace ON alert_events(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_events_filter ON alert_events(workspace_id, status, level, rule_key, created_at DESC);

ALTER TABLE usage_logs ADD COLUMN prompt_tokens REAL;
ALTER TABLE usage_logs ADD COLUMN completion_tokens REAL;
ALTER TABLE usage_logs ADD COLUMN parse_status TEXT;
ALTER TABLE usage_logs ADD COLUMN parse_note TEXT;
