-- Bugcontrol schema

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    handle TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    offers_bounties INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(platform, handle)
);

CREATE TABLE IF NOT EXISTS scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    asset_identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL DEFAULT '',
    eligible_for_bounty INTEGER NOT NULL DEFAULT 0,
    eligible_for_submission INTEGER NOT NULL DEFAULT 1,
    in_scope INTEGER NOT NULL DEFAULT 1,
    instruction TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(program_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_id);
CREATE INDEX IF NOT EXISTS idx_scopes_asset ON scopes(asset_identifier);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    platform TEXT NOT NULL,
    program_handle TEXT NOT NULL,
    program_name TEXT NOT NULL DEFAULT '',
    program_url TEXT NOT NULL DEFAULT '',
    scope_id INTEGER REFERENCES scopes(id) ON DELETE SET NULL,
    asset_identifier TEXT NOT NULL DEFAULT '',
    asset_type TEXT NOT NULL DEFAULT '',
    eligible_for_bounty INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    alerted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(platform, program_handle);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    tool TEXT NOT NULL,
    status TEXT NOT NULL,
    targets_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    exit_code INTEGER,
    summary TEXT NOT NULL DEFAULT '',
    log_path TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_jobs_finding ON jobs(finding_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    agent_id TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    prompt TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    dashboard_url TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    finished_at TEXT,
    error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_finding ON agent_runs(finding_id);

CREATE TABLE IF NOT EXISTS scan_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_finding ON scan_artifacts(finding_id);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
