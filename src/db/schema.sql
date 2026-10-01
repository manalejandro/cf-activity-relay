-- cf-activity-relay D1 schema
-- All statements are idempotent; the Worker also applies this schema lazily on
-- cold start so a fresh deployment works without a manual migration step.

CREATE TABLE IF NOT EXISTS relay_config (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscribers (
	domain TEXT PRIMARY KEY,
	inbox_url TEXT NOT NULL,
	activity_id TEXT NOT NULL,
	actor_id TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS followers (
	domain TEXT PRIMARY KEY,
	inbox_url TEXT NOT NULL,
	activity_id TEXT NOT NULL,
	actor_id TEXT NOT NULL,
	mutually_follow INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_requests (
	domain TEXT PRIMARY KEY,
	inbox_url TEXT NOT NULL,
	activity_id TEXT NOT NULL,
	type TEXT NOT NULL,
	actor TEXT NOT NULL,
	object TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS publishers (
	domain TEXT PRIMARY KEY,
	actor_id TEXT NOT NULL,
	inbox_url TEXT,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	last_activity_id TEXT,
	last_activity_type TEXT,
	activity_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS blocked_domains (
	domain TEXT PRIMARY KEY,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS limited_domains (
	domain TEXT PRIMARY KEY,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receiver_health (
	domain TEXT PRIMARY KEY,
	last_success_at TEXT,
	last_failure_at TEXT,
	consecutive_failures INTEGER NOT NULL DEFAULT 0,
	total_successes INTEGER NOT NULL DEFAULT 0,
	total_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS activity_payloads (
	id TEXT PRIMARY KEY,
	body TEXT NOT NULL,
	remain_count INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS canonical_activities (
	hash TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signature_nonces (
	hash TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signature_capabilities (
	origin TEXT NOT NULL,
	scope TEXT NOT NULL,
	profile TEXT NOT NULL,
	observed_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY (origin, scope)
);

CREATE TABLE IF NOT EXISTS delivered_activities (
	activity_id TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS inbound_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	at INTEGER NOT NULL,
	type TEXT NOT NULL,
	actor_domain TEXT NOT NULL,
	activity_id TEXT,
	status INTEGER NOT NULL,
	reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_payloads_created ON activity_payloads (created_at);
CREATE INDEX IF NOT EXISTS idx_canonical_created ON canonical_activities (created_at);
CREATE INDEX IF NOT EXISTS idx_nonces_created ON signature_nonces (created_at);
CREATE INDEX IF NOT EXISTS idx_delivered_created ON delivered_activities (created_at);
CREATE INDEX IF NOT EXISTS idx_capabilities_expires ON signature_capabilities (expires_at);
CREATE INDEX IF NOT EXISTS idx_inbound_log_at ON inbound_log (at);
