import type { PendingRequest, Publisher, Receiver, ReceiverHealth, RelaySettings } from '../types';

const SCHEMA_STATEMENTS = [
	`CREATE TABLE IF NOT EXISTS relay_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS subscribers (domain TEXT PRIMARY KEY, inbox_url TEXT NOT NULL, activity_id TEXT NOT NULL, actor_id TEXT NOT NULL, created_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS followers (domain TEXT PRIMARY KEY, inbox_url TEXT NOT NULL, activity_id TEXT NOT NULL, actor_id TEXT NOT NULL, mutually_follow INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS pending_requests (domain TEXT PRIMARY KEY, inbox_url TEXT NOT NULL, activity_id TEXT NOT NULL, type TEXT NOT NULL, actor TEXT NOT NULL, object TEXT NOT NULL, created_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS publishers (domain TEXT PRIMARY KEY, actor_id TEXT NOT NULL, inbox_url TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_activity_id TEXT, last_activity_type TEXT, activity_count INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT PRIMARY KEY, created_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS limited_domains (domain TEXT PRIMARY KEY, created_at TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS receiver_health (domain TEXT PRIMARY KEY, last_success_at TEXT, last_failure_at TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0, total_successes INTEGER NOT NULL DEFAULT 0, total_failures INTEGER NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS activity_payloads (id TEXT PRIMARY KEY, body TEXT NOT NULL, remain_count INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS canonical_activities (hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS signature_nonces (hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS signature_capabilities (origin TEXT NOT NULL, scope TEXT NOT NULL, profile TEXT NOT NULL, observed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (origin, scope))`,
	`CREATE TABLE IF NOT EXISTS delivered_activities (activity_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS idx_payloads_created ON activity_payloads (created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_canonical_created ON canonical_activities (created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_nonces_created ON signature_nonces (created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_delivered_created ON delivered_activities (created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_capabilities_expires ON signature_capabilities (expires_at)`,
];

let schemaPromise: Promise<void> | null = null;

/**
 * Applies the idempotent schema once per Worker isolate. Deployments may also
 * run `npm run db:migrate` to create the tables ahead of time.
 */
export function ensureSchema(db: D1Database): Promise<void> {
	if (!schemaPromise) {
		schemaPromise = db
			.batch(SCHEMA_STATEMENTS.map((statement) => db.prepare(statement)))
			.then(() => undefined)
			.catch((error) => {
				schemaPromise = null;
				throw error;
			});
	}
	return schemaPromise;
}

function nowIso(): string {
	return new Date().toISOString();
}

function unixNow(): number {
	return Math.floor(Date.now() / 1000);
}

// ---------------------------------------------------------------------------
// Configuration and identity
// ---------------------------------------------------------------------------

export async function getConfigValue(db: D1Database, key: string): Promise<string | null> {
	const row = await db.prepare('SELECT value FROM relay_config WHERE key = ?').bind(key).first<{ value: string }>();
	return row?.value ?? null;
}

export async function setConfigValue(db: D1Database, key: string, value: string): Promise<void> {
	await db
		.prepare('INSERT INTO relay_config (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at')
		.bind(key, value, nowIso())
		.run();
}

export interface StoredIdentity {
	privateKeyPem: string;
	publicKeyPem: string;
}

export async function getStoredIdentity(db: D1Database): Promise<StoredIdentity | null> {
	const rows = await db
		.prepare("SELECT key, value FROM relay_config WHERE key IN ('private_key_pem', 'public_key_pem')")
		.all<{ key: string; value: string }>();
	const map = new Map((rows.results ?? []).map((row) => [row.key, row.value]));
	const privateKeyPem = map.get('private_key_pem');
	const publicKeyPem = map.get('public_key_pem');
	if (!privateKeyPem || !publicKeyPem) return null;
	return { privateKeyPem, publicKeyPem };
}

export async function storeIdentity(db: D1Database, identity: StoredIdentity): Promise<void> {
	const timestamp = nowIso();
	await db.batch([
		db
			.prepare("INSERT INTO relay_config (key, value, updated_at) VALUES ('private_key_pem', ?, ?) ON CONFLICT(key) DO NOTHING")
			.bind(identity.privateKeyPem, timestamp),
		db
			.prepare("INSERT INTO relay_config (key, value, updated_at) VALUES ('public_key_pem', ?, ?) ON CONFLICT(key) DO NOTHING")
			.bind(identity.publicKeyPem, timestamp),
	]);
}

export async function loadRelaySettings(db: D1Database): Promise<RelaySettings | null> {
	const rows = await db
		.prepare("SELECT key, value FROM relay_config WHERE key IN ('person_only', 'manually_accept')")
		.all<{ key: string; value: string }>();
	if (!rows.results || rows.results.length === 0) return null;
	const map = new Map(rows.results.map((row) => [row.key, row.value]));
	return { personOnly: map.get('person_only') === '1', manuallyAccept: map.get('manually_accept') === '1' };
}

export async function saveRelaySettings(db: D1Database, settings: Partial<RelaySettings>): Promise<void> {
	const writes: D1PreparedStatement[] = [];
	if (settings.personOnly !== undefined) {
		writes.push(db.prepare("INSERT INTO relay_config (key, value, updated_at) VALUES ('person_only', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(settings.personOnly ? '1' : '0', nowIso()));
	}
	if (settings.manuallyAccept !== undefined) {
		writes.push(db.prepare("INSERT INTO relay_config (key, value, updated_at) VALUES ('manually_accept', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(settings.manuallyAccept ? '1' : '0', nowIso()));
	}
	if (writes.length > 0) await db.batch(writes);
}

// ---------------------------------------------------------------------------
// Receivers: traditional subscribers and follower-style followers
// ---------------------------------------------------------------------------

interface ReceiverRow {
	domain: string;
	inbox_url: string;
	activity_id: string;
	actor_id: string;
	mutually_follow?: number;
}

function toReceiver(row: ReceiverRow, kind: 'subscriber' | 'follower'): Receiver {
	return {
		domain: row.domain,
		inboxUrl: row.inbox_url,
		activityId: row.activity_id,
		actorId: row.actor_id,
		kind,
		mutuallyFollow: row.mutually_follow === 1,
	};
}

export async function listSubscribers(db: D1Database): Promise<Receiver[]> {
	const rows = await db.prepare('SELECT domain, inbox_url, activity_id, actor_id FROM subscribers ORDER BY domain').all<ReceiverRow>();
	return (rows.results ?? []).map((row) => toReceiver(row, 'subscriber'));
}

export async function listFollowers(db: D1Database): Promise<Receiver[]> {
	const rows = await db.prepare('SELECT domain, inbox_url, activity_id, actor_id, mutually_follow FROM followers ORDER BY domain').all<ReceiverRow>();
	return (rows.results ?? []).map((row) => toReceiver(row, 'follower'));
}

export async function listReceivers(db: D1Database): Promise<Receiver[]> {
	const [subscribers, followers] = await Promise.all([listSubscribers(db), listFollowers(db)]);
	return [...subscribers, ...followers];
}

export async function getSubscriber(db: D1Database, domain: string): Promise<Receiver | null> {
	const row = await db.prepare('SELECT domain, inbox_url, activity_id, actor_id FROM subscribers WHERE domain = ?').bind(domain).first<ReceiverRow>();
	return row ? toReceiver(row, 'subscriber') : null;
}

export async function getFollower(db: D1Database, domain: string): Promise<Receiver | null> {
	const row = await db
		.prepare('SELECT domain, inbox_url, activity_id, actor_id, mutually_follow FROM followers WHERE domain = ?')
		.bind(domain)
		.first<ReceiverRow>();
	return row ? toReceiver(row, 'follower') : null;
}

export async function addSubscriber(db: D1Database, receiver: { domain: string; inboxUrl: string; activityId: string; actorId: string }): Promise<void> {
	await db
		.prepare(
			`INSERT INTO subscribers (domain, inbox_url, activity_id, actor_id, created_at) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(domain) DO UPDATE SET inbox_url = excluded.inbox_url, activity_id = excluded.activity_id, actor_id = excluded.actor_id`,
		)
		.bind(receiver.domain, receiver.inboxUrl, receiver.activityId, receiver.actorId, nowIso())
		.run();
}

export async function addFollower(
	db: D1Database,
	receiver: { domain: string; inboxUrl: string; activityId: string; actorId: string; mutuallyFollow?: boolean },
): Promise<void> {
	await db
		.prepare(
			`INSERT INTO followers (domain, inbox_url, activity_id, actor_id, mutually_follow, created_at) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(domain) DO UPDATE SET inbox_url = excluded.inbox_url, activity_id = excluded.activity_id, actor_id = excluded.actor_id`,
		)
		.bind(receiver.domain, receiver.inboxUrl, receiver.activityId, receiver.actorId, receiver.mutuallyFollow ? 1 : 0, nowIso())
		.run();
}

export async function deleteSubscriber(db: D1Database, domain: string): Promise<void> {
	await db.prepare('DELETE FROM subscribers WHERE domain = ?').bind(domain).run();
}

export async function deleteFollower(db: D1Database, domain: string): Promise<void> {
	await db.prepare('DELETE FROM followers WHERE domain = ?').bind(domain).run();
}

/**
 * Updates the mutual-follow flag of an existing, complete follower record.
 * Returns false when the record is missing or incomplete; stale mutual-follow
 * responses must never create a follower as a side effect.
 */
export async function updateFollowerMutual(db: D1Database, domain: string, mutuallyFollow: boolean): Promise<boolean> {
	const result = await db
		.prepare(
			`UPDATE followers SET mutually_follow = ?
			 WHERE domain = ? AND inbox_url <> '' AND activity_id <> '' AND actor_id <> ''`,
		)
		.bind(mutuallyFollow ? 1 : 0, domain)
		.run();
	return (result.meta?.changes ?? 0) > 0;
}

export async function isSubscriberOrFollower(db: D1Database, domain: string): Promise<boolean> {
	const row = await db
		.prepare('SELECT 1 AS present FROM subscribers WHERE domain = ? UNION ALL SELECT 1 AS present FROM followers WHERE domain = ? LIMIT 1')
		.bind(domain, domain)
		.first<{ present: number }>();
	return row?.present === 1;
}

// ---------------------------------------------------------------------------
// Publishers
// ---------------------------------------------------------------------------

interface PublisherRow {
	domain: string;
	actor_id: string;
	inbox_url: string | null;
	first_seen: string;
	last_seen: string;
	last_activity_id: string | null;
	last_activity_type: string | null;
	activity_count: number;
}

function toPublisher(row: PublisherRow): Publisher {
	return {
		domain: row.domain,
		actorId: row.actor_id,
		inboxUrl: row.inbox_url,
		firstSeen: row.first_seen,
		lastSeen: row.last_seen,
		lastActivityId: row.last_activity_id,
		lastActivityType: row.last_activity_type,
		activityCount: row.activity_count,
	};
}

export async function listPublishers(db: D1Database): Promise<Publisher[]> {
	const rows = await db
		.prepare('SELECT domain, actor_id, inbox_url, first_seen, last_seen, last_activity_id, last_activity_type, activity_count FROM publishers ORDER BY domain')
		.all<PublisherRow>();
	return (rows.results ?? []).map(toPublisher);
}

export async function recordPublisher(
	db: D1Database,
	publisher: { domain: string; actorId: string; inboxUrl: string | null; activityId: string | null; activityType: string | null },
): Promise<void> {
	const timestamp = nowIso();
	await db
		.prepare(
			`INSERT INTO publishers (domain, actor_id, inbox_url, first_seen, last_seen, last_activity_id, last_activity_type, activity_count)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 1)
			 ON CONFLICT(domain) DO UPDATE SET
			   actor_id = excluded.actor_id,
			   inbox_url = excluded.inbox_url,
			   last_seen = excluded.last_seen,
			   last_activity_id = excluded.last_activity_id,
			   last_activity_type = excluded.last_activity_type,
			   activity_count = publishers.activity_count + 1`,
		)
		.bind(publisher.domain, publisher.actorId, publisher.inboxUrl, timestamp, timestamp, publisher.activityId, publisher.activityType)
		.run();
}

// ---------------------------------------------------------------------------
// Domain policy
// ---------------------------------------------------------------------------

export async function listBlockedDomains(db: D1Database): Promise<string[]> {
	const rows = await db.prepare('SELECT domain FROM blocked_domains ORDER BY domain').all<{ domain: string }>();
	return (rows.results ?? []).map((row) => row.domain);
}

export async function listLimitedDomains(db: D1Database): Promise<string[]> {
	const rows = await db.prepare('SELECT domain FROM limited_domains ORDER BY domain').all<{ domain: string }>();
	return (rows.results ?? []).map((row) => row.domain);
}

export async function isBlocked(db: D1Database, domain: string): Promise<boolean> {
	const row = await db.prepare('SELECT 1 AS present FROM blocked_domains WHERE domain = ?').bind(domain).first<{ present: number }>();
	return row?.present === 1;
}

export async function isLimited(db: D1Database, domain: string): Promise<boolean> {
	const row = await db.prepare('SELECT 1 AS present FROM limited_domains WHERE domain = ?').bind(domain).first<{ present: number }>();
	return row?.present === 1;
}

export async function setDomainPolicy(db: D1Database, table: 'blocked_domains' | 'limited_domains', domain: string, enabled: boolean): Promise<void> {
	if (enabled) {
		await db.prepare(`INSERT INTO ${table} (domain, created_at) VALUES (?, ?) ON CONFLICT(domain) DO NOTHING`).bind(domain, nowIso()).run();
	} else {
		await db.prepare(`DELETE FROM ${table} WHERE domain = ?`).bind(domain).run();
	}
}

// ---------------------------------------------------------------------------
// Pending manual approvals
// ---------------------------------------------------------------------------

interface PendingRow {
	domain: string;
	inbox_url: string;
	activity_id: string;
	type: string;
	actor: string;
	object: string;
	created_at: string;
}

export async function listPending(db: D1Database): Promise<PendingRequest[]> {
	const rows = await db.prepare('SELECT * FROM pending_requests ORDER BY domain').all<PendingRow>();
	return (rows.results ?? []).map((row) => ({
		domain: row.domain,
		inboxUrl: row.inbox_url,
		activityId: row.activity_id,
		type: row.type,
		actor: row.actor,
		object: row.object,
		createdAt: row.created_at,
	}));
}

export async function getPending(db: D1Database, domain: string): Promise<PendingRequest | null> {
	const row = await db.prepare('SELECT * FROM pending_requests WHERE domain = ?').bind(domain).first<PendingRow>();
	if (!row) return null;
	return {
		domain: row.domain,
		inboxUrl: row.inbox_url,
		activityId: row.activity_id,
		type: row.type,
		actor: row.actor,
		object: row.object,
		createdAt: row.created_at,
	};
}

export async function putPending(db: D1Database, request: PendingRequest): Promise<void> {
	await db
		.prepare(
			`INSERT INTO pending_requests (domain, inbox_url, activity_id, type, actor, object, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(domain) DO UPDATE SET inbox_url = excluded.inbox_url, activity_id = excluded.activity_id, type = excluded.type, actor = excluded.actor, object = excluded.object, created_at = excluded.created_at`,
		)
		.bind(request.domain, request.inboxUrl, request.activityId, request.type, request.actor, request.object, request.createdAt)
		.run();
}

export async function deletePending(db: D1Database, domain: string): Promise<void> {
	await db.prepare('DELETE FROM pending_requests WHERE domain = ?').bind(domain).run();
}

// ---------------------------------------------------------------------------
// Receiver health
// ---------------------------------------------------------------------------

export async function recordReceiverSuccess(db: D1Database, domain: string): Promise<void> {
	await db
		.prepare(
			`INSERT INTO receiver_health (domain, last_success_at, consecutive_failures, total_successes, total_failures)
			 VALUES (?, ?, 0, 1, 0)
			 ON CONFLICT(domain) DO UPDATE SET last_success_at = excluded.last_success_at, consecutive_failures = 0, total_successes = receiver_health.total_successes + 1`,
		)
		.bind(domain, nowIso())
		.run();
}

export async function recordReceiverFailure(db: D1Database, domain: string): Promise<void> {
	await db
		.prepare(
			`INSERT INTO receiver_health (domain, last_failure_at, consecutive_failures, total_successes, total_failures)
			 VALUES (?, ?, 1, 0, 1)
			 ON CONFLICT(domain) DO UPDATE SET last_failure_at = excluded.last_failure_at, consecutive_failures = receiver_health.consecutive_failures + 1, total_failures = receiver_health.total_failures + 1`,
		)
		.bind(domain, nowIso())
		.run();
}

export async function listReceiverHealth(db: D1Database, domains: string[]): Promise<Map<string, ReceiverHealth>> {
	if (domains.length === 0) return new Map();
	const placeholders = domains.map(() => '?').join(', ');
	const rows = await db
		.prepare(`SELECT * FROM receiver_health WHERE domain IN (${placeholders})`)
		.bind(...domains)
		.all<{
			domain: string;
			last_success_at: string | null;
			last_failure_at: string | null;
			consecutive_failures: number;
			total_successes: number;
			total_failures: number;
		}>();
	const map = new Map<string, ReceiverHealth>();
	for (const row of rows.results ?? []) {
		map.set(row.domain, {
			domain: row.domain,
			lastSuccessAt: row.last_success_at,
			lastFailureAt: row.last_failure_at,
			consecutiveFailures: row.consecutive_failures,
			totalSuccesses: row.total_successes,
			totalFailures: row.total_failures,
		});
	}
	return map;
}

// ---------------------------------------------------------------------------
// Fan-out payloads
// ---------------------------------------------------------------------------

export async function createPayload(db: D1Database, id: string, body: string, remainCount: number): Promise<void> {
	await db
		.prepare('INSERT INTO activity_payloads (id, body, remain_count, created_at) VALUES (?, ?, ?, ?)')
		.bind(id, body, remainCount, unixNow())
		.run();
}

export async function getPayload(db: D1Database, id: string): Promise<{ body: string; remainCount: number } | null> {
	const row = await db.prepare('SELECT body, remain_count FROM activity_payloads WHERE id = ?').bind(id).first<{ body: string; remain_count: number }>();
	return row ? { body: row.body, remainCount: row.remain_count } : null;
}

export async function decrementPayload(db: D1Database, id: string): Promise<void> {
	await db.batch([
		db.prepare('UPDATE activity_payloads SET remain_count = remain_count - 1 WHERE id = ?').bind(id),
		db.prepare('DELETE FROM activity_payloads WHERE id = ? AND remain_count <= 0').bind(id),
	]);
}

export async function deletePayload(db: D1Database, id: string): Promise<void> {
	await db.prepare('DELETE FROM activity_payloads WHERE id = ?').bind(id).run();
}

export async function countPayloads(db: D1Database): Promise<number> {
	const row = await db.prepare('SELECT COUNT(*) AS total FROM activity_payloads').first<{ total: number }>();
	return row?.total ?? 0;
}

// ---------------------------------------------------------------------------
// Loop guards, replay protection and capability evidence
// ---------------------------------------------------------------------------

/** Reserves a canonical activity hash. Returns false when already reserved. */
export async function reserveCanonical(db: D1Database, hash: string): Promise<boolean> {
	const result = await db
		.prepare('INSERT INTO canonical_activities (hash, created_at) VALUES (?, ?) ON CONFLICT(hash) DO NOTHING')
		.bind(hash, unixNow())
		.run();
	return (result.meta?.changes ?? 0) > 0;
}

export async function releaseCanonical(db: D1Database, hash: string): Promise<void> {
	await db.prepare('DELETE FROM canonical_activities WHERE hash = ?').bind(hash).run();
}

/** Reserves an inbound activity identifier for de-duplication. */
export async function reserveActivity(db: D1Database, activityId: string): Promise<boolean> {
	const result = await db
		.prepare('INSERT INTO delivered_activities (activity_id, created_at) VALUES (?, ?) ON CONFLICT(activity_id) DO NOTHING')
		.bind(activityId, unixNow())
		.run();
	return (result.meta?.changes ?? 0) > 0;
}

/** Reserves an RFC 9421 nonce. Returns false on replay. */
export async function reserveNonce(db: D1Database, hash: string): Promise<boolean> {
	const result = await db
		.prepare('INSERT INTO signature_nonces (hash, created_at) VALUES (?, ?) ON CONFLICT(hash) DO NOTHING')
		.bind(hash, unixNow())
		.run();
	return (result.meta?.changes ?? 0) > 0;
}

export async function getCapability(db: D1Database, origin: string, scope: 'fetch' | 'delivery'): Promise<'legacy' | 'rfc9421' | null> {
	const row = await db
		.prepare('SELECT profile, expires_at FROM signature_capabilities WHERE origin = ? AND scope = ?')
		.bind(origin, scope)
		.first<{ profile: string; expires_at: number }>();
	if (!row || row.expires_at <= unixNow()) return null;
	return row.profile === 'rfc9421' ? 'rfc9421' : row.profile === 'legacy' ? 'legacy' : null;
}

/** Loads every unexpired capability for a scope in a single query. */
export async function listCapabilities(db: D1Database, scope: 'fetch' | 'delivery'): Promise<Map<string, 'legacy' | 'rfc9421'>> {
	const rows = await db
		.prepare('SELECT origin, profile FROM signature_capabilities WHERE scope = ? AND expires_at > ?')
		.bind(scope, unixNow())
		.all<{ origin: string; profile: string }>();
	const map = new Map<string, 'legacy' | 'rfc9421'>();
	for (const row of rows.results ?? []) {
		map.set(row.origin, row.profile === 'rfc9421' ? 'rfc9421' : 'legacy');
	}
	return map;
}

export async function setCapability(
	db: D1Database,
	origin: string,
	scope: 'fetch' | 'delivery',
	profile: 'legacy' | 'rfc9421',
	ttlSeconds: number,
): Promise<void> {
	const now = unixNow();
	await db
		.prepare(
			`INSERT INTO signature_capabilities (origin, scope, profile, observed_at, expires_at) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(origin, scope) DO UPDATE SET profile = excluded.profile, observed_at = excluded.observed_at, expires_at = excluded.expires_at`,
		)
		.bind(origin, scope, profile, now, now + ttlSeconds)
		.run();
}

/** Deletes expired ephemeral rows. Returns the number of cleaned categories. */
export async function cleanupExpired(db: D1Database): Promise<void> {
	const now = unixNow();
	await db.batch([
		db.prepare('DELETE FROM activity_payloads WHERE created_at < ?').bind(now - 900),
		db.prepare('DELETE FROM canonical_activities WHERE created_at < ?').bind(now - 900),
		db.prepare('DELETE FROM signature_nonces WHERE created_at < ?').bind(now - 600),
		db.prepare('DELETE FROM delivered_activities WHERE created_at < ?').bind(now - 86400),
		db.prepare('DELETE FROM signature_capabilities WHERE expires_at < ?').bind(now - 3600),
	]);
}
