import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateRsaKeyPair } from '../src/crypto/keys';
import { signLegacyRequest } from '../src/crypto/legacy';
import { signRfc9421Request } from '../src/crypto/rfc9421';

const RELAY = 'https://relay.manalejandro.com';
const REMOTE_ACTOR = 'https://remote.example/actor';
const REMOTE_KEY = `${REMOTE_ACTOR}#main-key`;
const REMOTE_INBOX = 'https://remote.example/inbox';
const PERSON_ACTOR = 'https://remote.example/users/alice';
const PERSON_KEY = `${PERSON_ACTOR}#main-key`;
const DELETED_ACTOR = 'https://remote.example/users/deleted';
const DELETED_KEY = `${DELETED_ACTOR}#main-key`;
const PUBLIC_ADDRESS = 'https://www.w3.org/ns/activitystreams#Public';

let privateKeyPem = '';
let publicKeyPem = '';

/** Intercepts every outbound federation request the worker makes. */
function stubFederation(): ReturnType<typeof vi.fn> {
	const mock = vi.fn(async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
		// A deleted account: its actor document is gone, so its key can never be
		// resolved. Mastodon still signs the account deletion notice with it.
		if (url === DELETED_ACTOR) return new Response('gone', { status: 410 });
		if (url === REMOTE_ACTOR || url === PERSON_ACTOR) {
			const isPerson = url === PERSON_ACTOR;
			return new Response(
				JSON.stringify({
					'@context': 'https://www.w3.org/ns/activitystreams',
					id: url,
					type: isPerson ? 'Person' : 'Application',
					inbox: isPerson ? 'https://remote.example/users/alice/inbox' : REMOTE_INBOX,
					endpoints: { sharedInbox: REMOTE_INBOX },
					publicKey: { id: isPerson ? PERSON_KEY : REMOTE_KEY, owner: url, publicKeyPem },
				}),
				{ headers: { 'Content-Type': 'application/activity+json' } },
			);
		}
		if (url === REMOTE_INBOX || url === 'https://remote.example/users/alice/inbox') return new Response('', { status: 202 });
		return new Response('not found', { status: 404 });
	});
	vi.stubGlobal('fetch', mock);
	return mock;
}

function followActivity(id: string): string {
	return JSON.stringify({
		'@context': 'https://www.w3.org/ns/activitystreams',
		id,
		type: 'Follow',
		actor: REMOTE_ACTOR,
		object: PUBLIC_ADDRESS,
	});
}

beforeAll(async () => {
	const pair = await generateRsaKeyPair(2048);
	privateKeyPem = pair.privateKeyPem;
	publicKeyPem = pair.publicKeyPem;
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('inbound inbox processing', () => {
	it('accepts a legacy-signed Follow and records the subscriber', async () => {
		stubFederation();
		const body = followActivity('https://remote.example/activities/follow-legacy');
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		const row = await env.DB.prepare('SELECT * FROM subscribers WHERE domain = ?').bind('remote.example').first<{ inbox_url: string; actor_id: string }>();
		expect(row?.inbox_url).toBe(REMOTE_INBOX);
		expect(row?.actor_id).toBe(REMOTE_ACTOR);
	});

	it('accepts an RFC 9421 signed Follow', async () => {
		stubFederation();
		const body = followActivity('https://remote.example/activities/follow-rfc9421');
		const signed = await signRfc9421Request({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);
	});

	it('rejects an unsigned activity', async () => {
		stubFederation();
		const response = await SELF.fetch(`${RELAY}/inbox`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/activity+json' },
			body: followActivity('https://remote.example/activities/unsigned'),
		});
		expect(response.status).toBe(400);
	});

	it('rejects a tampered legacy signature', async () => {
		stubFederation();
		const body = followActivity('https://remote.example/activities/tampered');
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		const tampered = JSON.stringify({ ...JSON.parse(body), object: 'https://relay.manalejandro.com/actor' });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body: tampered });
		expect(response.status).toBe(400);
	});

	it('removes a subscriber on Undo{Follow}', async () => {
		stubFederation();
		const followBody = followActivity('https://remote.example/activities/follow-undo');
		const signedFollow = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body: followBody, privateKeyPem, keyId: REMOTE_KEY });
		await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signedFollow, body: followBody });
		expect(await env.DB.prepare('SELECT 1 AS present FROM subscribers WHERE domain = ?').bind('remote.example').first()).toBeTruthy();

		const undoBody = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://remote.example/activities/undo-follow',
			type: 'Undo',
			actor: REMOTE_ACTOR,
			object: JSON.parse(followBody),
		});
		const signedUndo = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body: undoBody, privateKeyPem, keyId: REMOTE_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signedUndo, body: undoBody });
		expect(response.status).toBe(202);
		expect(await env.DB.prepare('SELECT 1 AS present FROM subscribers WHERE domain = ?').bind('remote.example').first()).toBeFalsy();
	});

	it('resolves its own actor locally and refuses self-subscription', async () => {
		// No federation fetch is stubbed: the relay actor must be resolved from
		// local state instead of a Worker subrequest to its own hostname.
		const { loadConfig } = await import('../src/config');
		const { getRelayIdentity } = await import('../src/ap/identity');
		const config = loadConfig(env as unknown as Parameters<typeof loadConfig>[0]);
		const identity = await getRelayIdentity(env as unknown as Parameters<typeof getRelayIdentity>[0], config);
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: `${config.actorId}/activities/self-follow`,
			type: 'Follow',
			actor: config.actorId,
			object: PUBLIC_ADDRESS,
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem: identity.privateKeyPem, keyId: identity.keyId });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);
		expect(await env.DB.prepare('SELECT 1 AS present FROM subscribers WHERE domain = ?').bind('relay.manalejandro.com').first()).toBeFalsy();
	});

	it('records inbound events in the audit trail', async () => {
		stubFederation();
		const body = followActivity('https://remote.example/activities/follow-audit');
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });

		const accepted = await env.DB.prepare('SELECT type, actor_domain, status FROM inbound_log ORDER BY id DESC LIMIT 1').first<{
			type: string;
			actor_domain: string;
			status: number;
		}>();
		expect(accepted).toMatchObject({ type: 'Follow', actor_domain: 'remote.example', status: 202 });

		await SELF.fetch(`${RELAY}/inbox`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/activity+json' },
			body: followActivity('https://remote.example/activities/follow-unsigned-audit'),
		});
		const rejected = await env.DB.prepare('SELECT type, actor_domain, status, reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{
			type: string;
			actor_domain: string;
			status: number;
			reason: string;
		}>();
		expect(rejected).toMatchObject({ type: 'Follow', actor_domain: 'remote.example', status: 400, reason: 'signature-missing' });
	});

	it('rejects a personal account following the relay actor', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://remote.example/activities/person-follow',
			type: 'Follow',
			actor: PERSON_ACTOR,
			object: `${RELAY}/actor`,
			to: [`${RELAY}/actor`],
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PERSON_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		// A personal account must never become a relay receiver: it would
		// receive every relayed public activity in its home timeline.
		expect(await env.DB.prepare('SELECT 1 AS present FROM followers WHERE domain = ?').bind('remote.example').first()).toBeFalsy();
		const entry = await env.DB.prepare('SELECT type, status, reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ type: string; status: number; reason: string }>();
		expect(entry).toMatchObject({ type: 'Follow', status: 202, reason: 'not-a-server-actor' });
	});

	it('provisions a subscriber through the admin API', async () => {
		stubFederation();
		const testEnv = env as unknown as { ADMIN_TOKEN?: string };
		testEnv.ADMIN_TOKEN = 'test-token';
		try {
			const response = await SELF.fetch(`${RELAY}/admin/subscribe`, {
				method: 'POST',
				headers: { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' },
				body: JSON.stringify({ actor: REMOTE_ACTOR }),
			});
			expect(response.status).toBe(200);
			const row = await env.DB.prepare('SELECT inbox_url, actor_id FROM subscribers WHERE domain = ?')
				.bind('remote.example')
				.first<{ inbox_url: string; actor_id: string }>();
			expect(row?.inbox_url).toBe(REMOTE_INBOX);
			expect(row?.actor_id).toBe(REMOTE_ACTOR);
		} finally {
			testEnv.ADMIN_TOKEN = undefined;
		}
	});

	it('acknowledges an unverifiable account deletion notice', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: `${DELETED_ACTOR}#delete`,
			type: 'Delete',
			actor: DELETED_ACTOR,
			to: [`${DELETED_ACTOR}/followers`],
			object: DELETED_ACTOR,
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: DELETED_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });

		// The account is gone, so the notice cannot be verified. A relay holds no
		// account state: acknowledge it without fan-out or publisher accounting.
		expect(response.status).toBe(202);
		const publishers = await env.DB.prepare('SELECT COUNT(*) AS total FROM publishers').first<{ total: number }>();
		expect(publishers?.total).toBe(0);
		const entry = await env.DB.prepare('SELECT type, status, reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ type: string; status: number; reason: string }>();
		expect(entry).toMatchObject({ type: 'Delete', status: 202, reason: 'unverifiable-delete' });
	});

	it('still rejects other activities whose signer key is gone', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://remote.example/activities/ghost-create',
			type: 'Create',
			actor: DELETED_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: 'https://remote.example/notes/ghost', type: 'Note' },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: DELETED_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(400);
	});

	it('relays a public Delete as a relay-authored Announce', async () => {
		// Mirrors the reference `relay_activity_wrapper_test.go` case: an
		// unsigned public Delete is wrapped in a relay-signed Announce that
		// targets the relay followers, and the source body is never forwarded.
		stubFederation();
		await env.DB.prepare(
			`INSERT INTO subscribers (domain, inbox_url, activity_id, actor_id, created_at) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(domain) DO NOTHING`,
		)
			.bind('receiver.example', 'https://receiver.example/inbox', 'https://receiver.example/activities/follow', 'https://receiver.example/actor', new Date().toISOString())
			.run();

		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://remote.example/activities/delete-1',
			type: 'Delete',
			actor: REMOTE_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: 'https://remote.example/notes/3', type: 'Tombstone' },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		const payload = await env.DB.prepare('SELECT body FROM activity_payloads WHERE body LIKE ? ORDER BY created_at DESC LIMIT 1')
			.bind('%notes/3%')
			.first<{ body: string }>();
		expect(payload).toBeTruthy();
		const announce = JSON.parse(payload?.body ?? '{}') as Record<string, unknown>;
		expect(announce.type).toBe('Announce');
		expect(announce.actor).toBe(`${RELAY}/actor`);
		expect(announce.object).toBe('https://remote.example/notes/3');
		expect(announce.to).toEqual([`${RELAY}/actor/followers`]);
		expect(payload?.body).not.toContain('Tombstone');

		const publisher = await env.DB.prepare('SELECT last_activity_type FROM publishers WHERE domain = ?').bind('remote.example').first<{ last_activity_type: string }>();
		expect(publisher?.last_activity_type).toBe('Delete');
	});

	it('does not fan out an activity that is only public in cc', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://remote.example/activities/unlisted',
			type: 'Create',
			actor: REMOTE_ACTOR,
			to: ['https://remote.example/actor/followers'],
			cc: [PUBLIC_ADDRESS],
			object: { id: 'https://remote.example/notes/1', type: 'Note' },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		// The publisher is accounted for, but the unlisted activity was never
		// wrapped into a relay Announce payload.
		const publisher = await env.DB.prepare('SELECT * FROM publishers WHERE domain = ?').bind('remote.example').first();
		expect(publisher).toBeTruthy();
		const payload = await env.DB.prepare('SELECT COUNT(*) AS total FROM activity_payloads WHERE body LIKE ?')
			.bind('%https://remote.example/notes/1%')
			.first<{ total: number }>();
		expect(payload?.total).toBe(0);
	});

	it('fans a public Create out to registered receivers', async () => {
		stubFederation();
		await env.DB.prepare(
			`INSERT INTO subscribers (domain, inbox_url, activity_id, actor_id, created_at) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(domain) DO NOTHING`,
		)
			.bind('receiver.example', 'https://receiver.example/inbox', 'https://receiver.example/activities/follow', 'https://receiver.example/actor', new Date().toISOString())
			.run();

		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://remote.example/activities/create-1',
			type: 'Create',
			actor: REMOTE_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: 'https://remote.example/notes/2', type: 'Note', content: 'hello' },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: REMOTE_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		const payload = await env.DB.prepare('SELECT body, remain_count FROM activity_payloads ORDER BY created_at DESC LIMIT 1').first<{ body: string; remain_count: number }>();
		expect(payload).toBeTruthy();
		expect(payload?.remain_count).toBe(1);
		const announce = JSON.parse(payload?.body ?? '{}') as Record<string, unknown>;
		expect(announce.type).toBe('Announce');
		expect(announce.actor).toBe(`${RELAY}/actor`);
		expect(announce.object).toBe('https://remote.example/notes/2');
	});
});
