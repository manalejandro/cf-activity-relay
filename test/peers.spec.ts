import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateRsaKeyPair } from '../src/crypto/keys';
import { signLegacyRequest } from '../src/crypto/legacy';
import { loadConfig } from '../src/config';

// Relay-to-relay peering: this relay subscribes to an upstream relay and
// re-announces the peer's content after re-verifying it at the origin.
const CONFIG = loadConfig(env as unknown as Parameters<typeof loadConfig>[0]);
const RELAY = CONFIG.baseUrl;
const PUBLIC_ADDRESS = 'https://www.w3.org/ns/activitystreams#Public';

const PEER_ACTOR = 'https://peer.example/actor';
const PEER_KEY = `${PEER_ACTOR}#main-key`;
const PEER_INBOX = 'https://peer.example/inbox';
const PEER_DOMAIN = 'peer.example';

const ORIGIN_ACTOR = 'https://origin.example/actor';
const ORIGIN_INBOX = 'https://origin.example/inbox';
const NOTE = 'https://origin.example/notes/5';
const CREATE = 'https://origin.example/activities/9';
const FLAKY_NOTE = 'https://origin.example/notes/flaky';

const DOWN_INBOX = 'https://down.example/inbox';

let privateKeyPem = '';
let publicKeyPem = '';

function stubFederation(): ReturnType<typeof vi.fn> {
	let flakyCalls = 0;
	const mock = vi.fn(async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
		// Origin edge caches can 404 a brand new object: fail twice, then serve.
		if (url === FLAKY_NOTE) {
			flakyCalls += 1;
			if (flakyCalls <= 2) return new Response('{"error":"Not Found"}', { status: 404 });
			return new Response(
				JSON.stringify({
					'@context': 'https://www.w3.org/ns/activitystreams',
					id: `${FLAKY_NOTE}/activity`,
					type: 'Create',
					actor: ORIGIN_ACTOR,
					to: [PUBLIC_ADDRESS],
					object: { id: FLAKY_NOTE, type: 'Note', attributedTo: ORIGIN_ACTOR },
				}),
				{ headers: { 'Content-Type': 'application/activity+json' } },
			);
		}
		if (url === PEER_ACTOR || url === ORIGIN_ACTOR) {
			return new Response(
				JSON.stringify({
					'@context': 'https://www.w3.org/ns/activitystreams',
					id: url,
					type: 'Application',
					preferredUsername: url === PEER_ACTOR ? 'relay' : 'origin',
					inbox: url === PEER_ACTOR ? PEER_INBOX : ORIGIN_INBOX,
					endpoints: { sharedInbox: url === PEER_ACTOR ? PEER_INBOX : ORIGIN_INBOX },
					publicKey: { id: url === PEER_ACTOR ? PEER_KEY : `${url}#main-key`, owner: url, publicKeyPem },
				}),
				{ headers: { 'Content-Type': 'application/activity+json' } },
			);
		}
		if (url === NOTE) {
			return new Response(
				JSON.stringify({
					'@context': 'https://www.w3.org/ns/activitystreams',
					id: NOTE,
					type: 'Note',
					attributedTo: ORIGIN_ACTOR,
					to: [PUBLIC_ADDRESS],
					content: 'hello from the origin',
				}),
				{ headers: { 'Content-Type': 'application/activity+json' } },
			);
		}
		if (url === CREATE) {
			return new Response(
				JSON.stringify({
					'@context': 'https://www.w3.org/ns/activitystreams',
					id: CREATE,
					type: 'Create',
					actor: ORIGIN_ACTOR,
					to: [PUBLIC_ADDRESS],
					object: { id: NOTE, type: 'Note', attributedTo: ORIGIN_ACTOR },
				}),
				{ headers: { 'Content-Type': 'application/activity+json' } },
			);
		}
		if (url === PEER_INBOX || url === ORIGIN_INBOX || url === DOWN_INBOX) return new Response('', { status: 202 });
		return new Response('not found', { status: 404 });
	});
	vi.stubGlobal('fetch', mock);
	return mock;
}

function peerFollowId(): string {
	return `${RELAY}/actor/follows/${PEER_DOMAIN}`;
}

beforeAll(async () => {
	const pair = await generateRsaKeyPair(2048);
	privateKeyPem = pair.privateKeyPem;
	publicKeyPem = pair.publicKeyPem;
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('relay-to-relay peering', () => {
	it('rejects signer/actor splits from unknown domains', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: CREATE,
			type: 'Create',
			actor: ORIGIN_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: NOTE, type: 'Note', attributedTo: ORIGIN_ACTOR },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(400);
	});

	it('subscribes to an upstream peer relay', async () => {
		stubFederation();
		const testEnv = env as unknown as { ADMIN_TOKEN?: string };
		testEnv.ADMIN_TOKEN = 'test-token';
		try {
			const response = await SELF.fetch(`${RELAY}/admin/peers/subscribe`, {
				method: 'POST',
				headers: { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' },
				body: JSON.stringify({ relay: PEER_ACTOR }),
			});
			expect(response.status).toBe(200);
			const payload = (await response.json()) as Record<string, unknown>;
			expect(payload.status).toBe('pending');
			expect(payload.domain).toBe(PEER_DOMAIN);

			const peer = await env.DB.prepare('SELECT status, style, follow_id FROM peer_relays WHERE domain = ?').bind(PEER_DOMAIN).first<{
				status: string;
				style: string;
				follow_id: string;
			}>();
			expect(peer?.status).toBe('pending');
			expect(peer?.style).toBe('follower');
			expect(peer?.follow_id).toBe(peerFollowId());

			const queued = await env.DB.prepare('SELECT body FROM activity_payloads ORDER BY created_at DESC LIMIT 1').first<{ body: string }>();
			expect(queued?.body).toContain('"type":"Follow"');
			expect(queued?.body).toContain(PEER_ACTOR);
		} finally {
			testEnv.ADMIN_TOKEN = undefined;
		}
	});

	it('activates the peer when the Accept arrives', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://peer.example/activities/accept-1',
			type: 'Accept',
			actor: PEER_ACTOR,
			object: peerFollowId(),
			to: [CONFIG.actorId],
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);
		const peer = await env.DB.prepare('SELECT status FROM peer_relays WHERE domain = ?').bind(PEER_DOMAIN).first<{ status: string }>();
		expect(peer?.status).toBe('active');
	});

	it('answers the peer reciprocal Follow without re-following', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://peer.example/activities/follow-reciprocal',
			type: 'Follow',
			actor: PEER_ACTOR,
			object: CONFIG.actorId,
			to: [CONFIG.actorId],
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		// The peer is recorded as a follower, but no second outbound Follow is
		// queued: re-following an existing peer would ping-pong forever. Match
		// only top-level Follows authored by us (Accept replies embed the
		// peer's Follow as `object` and must not count). D1 caps LIKE patterns
		// at 50 bytes, so filter in JS.
		const follower = await env.DB.prepare('SELECT domain FROM followers WHERE domain = ?').bind(PEER_DOMAIN).first();
		expect(follower).toBeTruthy();
		const payloads = await env.DB.prepare('SELECT body FROM activity_payloads').all<{ body: string }>();
		const followCount = (payloads.results ?? []).filter(
			(row) => row.body.includes(`"actor":"${CONFIG.actorId}","type":"Follow"`) && row.body.includes('peer.example'),
		).length;
		expect(followCount).toBe(1);
		const last = await env.DB.prepare('SELECT body FROM activity_payloads ORDER BY created_at DESC LIMIT 1').first<{ body: string }>();
		expect(last?.body).toContain('"type":"Accept"');
	});

	it('chains peer-relayed content after re-verifying it at the origin', async () => {
		stubFederation();
		await env.DB.prepare(
			`INSERT INTO subscribers (domain, inbox_url, activity_id, actor_id, created_at) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(domain) DO NOTHING`,
		)
			.bind('down.example', DOWN_INBOX, 'https://down.example/activities/follow', 'https://down.example/actor', new Date().toISOString())
			.run();

		// The peer signs; the JSON actor is the origin: a signer/actor split
		// only accepted from active peers.
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: CREATE,
			type: 'Create',
			actor: ORIGIN_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: NOTE, type: 'Note', attributedTo: ORIGIN_ACTOR },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		const payload = await env.DB.prepare('SELECT body, remain_count FROM activity_payloads WHERE body LIKE ? ORDER BY created_at DESC LIMIT 1')
			.bind(`%"object":"${NOTE}"%`)
			.first<{ body: string; remain_count: number }>();
		expect(payload).toBeTruthy();
		expect(payload?.remain_count).toBe(1);
		const announce = JSON.parse(payload?.body ?? '{}') as Record<string, unknown>;
		expect(announce.type).toBe('Announce');
		expect(announce.actor).toBe(CONFIG.actorId);

		const publisher = await env.DB.prepare('SELECT domain FROM publishers WHERE domain = ?').bind('origin.example').first();
		expect(publisher).toBeTruthy();
	});

	it('de-duplicates repeated peer deliveries of the same object', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: `${CREATE}-retry`,
			type: 'Create',
			actor: ORIGIN_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: NOTE, type: 'Note', attributedTo: ORIGIN_ACTOR },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		const payloads = await env.DB.prepare('SELECT COUNT(*) AS total FROM activity_payloads WHERE body LIKE ?').bind(`%"object":"${NOTE}"%`).first<{ total: number }>();
		expect(payloads?.total).toBe(1);
		const entry = await env.DB.prepare('SELECT reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ reason: string }>();
		expect(entry?.reason).toBe('duplicate');
	});

	it('chains peer Announce wrappers addressed to the peer audience', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://peer.example/activities/announce-1',
			type: 'Announce',
			actor: PEER_ACTOR,
			object: CREATE,
			to: [`${PEER_ACTOR}/followers`],
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		const payload = await env.DB.prepare('SELECT body FROM activity_payloads WHERE body LIKE ? ORDER BY created_at DESC LIMIT 1')
			.bind(`%"object":"${CREATE}"%`)
			.first<{ body: string }>();
		expect(payload).toBeTruthy();
	});

	it('forwards peer-relayed deletion notices with an intact LD signature', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://origin.example/activities/delete-7',
			type: 'Delete',
			actor: ORIGIN_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: NOTE,
			signature: {
				type: 'RsaSignature2017',
				creator: `${ORIGIN_ACTOR}#main-key`,
				created: '2026-10-28T00:00:00Z',
				signatureValue: 'c2lnbmF0dXJl',
			},
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);

		// The verbatim body reaches traditional subscribers; no fetch of the
		// (deleted) object is attempted and no Announce wrapper is minted.
		const payload = await env.DB.prepare('SELECT body FROM activity_payloads ORDER BY created_at DESC LIMIT 1').first<{ body: string }>();
		expect(payload?.body).toBe(body);
		const entry = await env.DB.prepare('SELECT reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ reason: string }>();
		expect(entry?.reason).toBe('forwarded-delete');
	});

	it('drops unsigned peer-relayed deletion notices', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://origin.example/activities/delete-8',
			type: 'Delete',
			actor: ORIGIN_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: NOTE,
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);
		const entry = await env.DB.prepare('SELECT reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ reason: string }>();
		expect(entry?.reason).toBe('delete-unverifiable');
	});

	it('retries transient 404s while chaining a peer wrapper', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://peer.example/activities/announce-flaky',
			type: 'Announce',
			actor: PEER_ACTOR,
			object: FLAKY_NOTE,
			to: [`${PEER_ACTOR}/followers`],
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(202);
		const payload = await env.DB.prepare('SELECT body FROM activity_payloads WHERE body LIKE ? ORDER BY created_at DESC LIMIT 1')
			.bind('%notes/flaky%')
			.first<{ body: string }>();
		expect(payload).toBeTruthy();
		const entry = await env.DB.prepare('SELECT reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ reason: string }>();
		expect(entry?.reason).toBe('chained');
	}, 15000);

	it('acknowledges without retrying when the referenced object is unfetchable', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: 'https://peer.example/activities/announce-gone',
			type: 'Announce',
			actor: PEER_ACTOR,
			object: 'https://origin.example/activities/gone',
			to: [`${PEER_ACTOR}/followers`],
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		// A missing origin object is unprocessable, not a client error: answer
		// 202 so the peer does not retry it forever.
		expect(response.status).toBe(202);
		const entry = await env.DB.prepare('SELECT reason FROM inbound_log ORDER BY id DESC LIMIT 1').first<{ reason: string }>();
		expect(entry?.reason).toBe('referenced-unfetchable');
	}, 15000);

	it('drops the peering and notifies the peer on unsubscribe', async () => {
		stubFederation();
		const testEnv = env as unknown as { ADMIN_TOKEN?: string };
		testEnv.ADMIN_TOKEN = 'test-token';
		try {
			const response = await SELF.fetch(`${RELAY}/admin/peers/unsubscribe`, {
				method: 'POST',
				headers: { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' },
				body: JSON.stringify({ domain: PEER_DOMAIN }),
			});
			expect(response.status).toBe(200);
			const peer = await env.DB.prepare('SELECT 1 AS present FROM peer_relays WHERE domain = ?').bind(PEER_DOMAIN).first();
			expect(peer).toBeFalsy();

			const queued = await env.DB.prepare('SELECT body FROM activity_payloads ORDER BY created_at DESC LIMIT 1').first<{ body: string }>();
			expect(queued?.body).toContain('"type":"Undo"');
			expect(queued?.body).toContain(peerFollowId());
		} finally {
			testEnv.ADMIN_TOKEN = undefined;
		}
	});

	it('rejects signer/actor splits again once the peer is gone', async () => {
		stubFederation();
		const body = JSON.stringify({
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: `${CREATE}-after-unpeer`,
			type: 'Create',
			actor: ORIGIN_ACTOR,
			to: [PUBLIC_ADDRESS],
			object: { id: NOTE, type: 'Note', attributedTo: ORIGIN_ACTOR },
		});
		const signed = await signLegacyRequest({ method: 'POST', url: `${RELAY}/inbox`, body, privateKeyPem, keyId: PEER_KEY });
		const response = await SELF.fetch(`${RELAY}/inbox`, { method: 'POST', headers: signed, body });
		expect(response.status).toBe(400);
	});
});
