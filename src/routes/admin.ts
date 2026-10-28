/**
 * Small administrative API replacing the reference CLI.
 *
 * Enabled only when `ADMIN_TOKEN` is configured; every request must present
 * `Authorization: Bearer <ADMIN_TOKEN>`.
 */
import { PUBLIC_ADDRESS, type RelayConfig } from '../config';
import type { Env } from '../env';
import { buildRelayActor } from '../ap/actor';
import { relayFollow, relayReply, relayUndoFollow, relayUpdate } from '../ap/builders';
import { enqueueDeliveries, enqueueFanOut } from '../ap/fanout';
import { timingSafeEqual } from '../crypto/digest';
import {
	addFollower,
	addSubscriber,
	deleteFollower,
	deletePending,
	deleteSubscriber,
	getFollower,
	getPending,
	isLimited,
	listBlockedDomains,
	listFollowers,
	listInboundLog,
	listLimitedDomains,
	listPending,
	listPublishers,
	listSubscribers,
	loadRelaySettings,
	saveRelaySettings,
	setDomainPolicy,
} from '../store/repo';
import type { APActivity } from '../types';
import { hostOf } from '../utils/domains';
import { jsonResponse, notFound, readBodyBounded, textResponse } from '../utils/http';

const ADMIN_BODY_LIMIT_BYTES = 64 * 1024;
const ADMIN_MAX_FAILED_ATTEMPTS = 20;
const ADMIN_LOCKOUT_SECONDS = 300;

function unauthorized(): Response {
	return textResponse('unauthorized', 401, { headers: { 'WWW-Authenticate': 'Bearer' } });
}

function safeDecode(value: string): string | null {
	try {
		return decodeURIComponent(value);
	} catch {
		return null;
	}
}

async function readJsonBody(request: Request): Promise<Record<string, unknown> | null> {
	const text = await readBodyBounded(request, ADMIN_BODY_LIMIT_BYTES);
	if (text === null) return null;
	try {
		if (!text) return {};
		const parsed: unknown = JSON.parse(text);
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
		return parsed as Record<string, unknown>;
	} catch {
		return null;
	}
}

export async function handleAdmin(env: Env, config: RelayConfig, request: Request, url: URL): Promise<Response> {
	if (!config.adminToken) return notFound();
	const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
	const failKey = `admin-fail:${ip}`;
	const failures = Number.parseInt((await env.CACHE.get(failKey)) ?? '0', 10) || 0;
	if (failures >= ADMIN_MAX_FAILED_ATTEMPTS) {
		return textResponse('too many failed attempts', 429, { headers: { 'Retry-After': String(ADMIN_LOCKOUT_SECONDS) } });
	}
	const authorization = request.headers.get('authorization') ?? '';
	const presented = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : '';
	if (!timingSafeEqual(presented, config.adminToken)) {
		await env.CACHE.put(failKey, String(failures + 1), { expirationTtl: ADMIN_LOCKOUT_SECONDS }).catch(() => undefined);
		return unauthorized();
	}
	await env.CACHE.delete(failKey).catch(() => undefined);

	const segments = url.pathname.split('/').filter(Boolean);
	// segments[0] === 'admin'
	const section = segments[1];

	if (section === 'log' && request.method === 'GET') {
		const requested = Number.parseInt(url.searchParams.get('limit') ?? '50', 10);
		const rows = await listInboundLog(env.DB, Number.isFinite(requested) ? requested : 50);
		return jsonResponse({
			entries: rows.map((row) => ({
				at: new Date(row.at * 1000).toISOString(),
				type: row.type,
				actor: row.actor_domain,
				activity_id: row.activity_id,
				status: row.status,
				reason: row.reason,
			})),
		});
	}

	if (section === 'subscribe' && request.method === 'POST') {
		// Operator-provisioned traditional subscription: resolves the actor's
		// shared inbox and registers it as a receiver, exactly like an accepted
		// `Follow` whose object is the Public collection.
		const body = await readJsonBody(request);
		const actorUrl = typeof body?.actor === 'string' ? body.actor : '';
		if (!actorUrl) return textResponse('actor is required', 400);
		const { getRelayIdentity } = await import('../ap/identity');
		const { fetchRemoteActor } = await import('../ap/remote');
		const identity = await getRelayIdentity(env, config);
		const actor = await fetchRemoteActor(env, config, identity, actorUrl);
		if (!actor) return textResponse('unable to resolve the actor', 404);
		const inboxUrl = actor.sharedInbox ?? actor.inbox;
		const domain = hostOf(actor.id);
		if (!inboxUrl || !domain) return textResponse('the actor has no usable inbox', 400);
		await addSubscriber(env.DB, { domain, inboxUrl, activityId: `urn:cf-activity-relay:admin:${Date.now()}`, actorId: actor.id });
		return jsonResponse({ status: 'subscribed', domain, inbox_url: inboxUrl, actor: actor.id });
	}

	if (section === 'unsubscribe' && request.method === 'POST') {
		const body = await readJsonBody(request);
		if (body === null) return textResponse('invalid or oversized JSON body', 400);
		const domain = typeof body?.domain === 'string' ? body.domain.trim().toLowerCase().replace(/\.$/, '') : '';
		if (!domain) return textResponse('domain is required', 400);
		const follower = await getFollower(env.DB, domain);
		await deleteSubscriber(env.DB, domain);
		await deleteFollower(env.DB, domain);
		await deletePending(env.DB, domain);
		if (follower) {
			await enqueueDeliveries(env, config, JSON.stringify(relayUndoFollow(config, follower.actorId)), [follower.inboxUrl]);
		}
		return jsonResponse({ status: 'unsubscribed', domain });
	}

	if (section === 'state' && request.method === 'GET') {
		const [subscribers, followers, pending, publishers, blocked, limited, settings] = await Promise.all([
			listSubscribers(env.DB),
			listFollowers(env.DB),
			listPending(env.DB),
			listPublishers(env.DB),
			listBlockedDomains(env.DB),
			listLimitedDomains(env.DB),
			loadRelaySettings(env.DB),
		]);
		return jsonResponse({
			domain: config.domain,
			settings: settings ?? { personOnly: config.personOnly, manuallyAccept: config.manuallyAccept },
			counts: {
				subscribers: subscribers.length,
				followers: followers.length,
				pending: pending.length,
				publishers: publishers.length,
				blocked: blocked.length,
				limited: limited.length,
			},
			subscribers,
			followers,
			pending,
			publishers,
			blocked,
			limited,
		});
	}

	if (section === 'pending' && segments.length === 4 && request.method === 'POST') {
		const decoded = safeDecode(segments[2]);
		if (decoded === null) return textResponse('invalid domain encoding', 400);
		const domain = decoded;
		const action = segments[3];
		if (action !== 'accept' && action !== 'reject') return notFound();
		const pending = await getPending(env.DB, domain);
		if (!pending) return notFound();
		const original: APActivity = { id: pending.activityId, type: 'Follow', actor: pending.actor, object: pending.object };
		if (action === 'reject') {
			await enqueueDeliveries(env, config, JSON.stringify(relayReply(config, original, 'Reject')), [pending.inboxUrl]);
			await deletePending(env.DB, domain);
			return jsonResponse({ status: 'rejected', domain });
		}
		if (pending.object === PUBLIC_ADDRESS) {
			await addSubscriber(env.DB, { domain: pending.domain, inboxUrl: pending.inboxUrl, activityId: pending.activityId, actorId: pending.actor });
		} else {
			await addFollower(env.DB, { domain: pending.domain, inboxUrl: pending.inboxUrl, activityId: pending.activityId, actorId: pending.actor });
		}
		await enqueueDeliveries(env, config, JSON.stringify(relayReply(config, original, 'Accept')), [pending.inboxUrl]);
		if (pending.object === config.actorId && !(await isLimited(env.DB, pending.domain))) {
			await enqueueDeliveries(env, config, JSON.stringify(relayFollow(config, pending.actor)), [pending.inboxUrl]);
		}
		await deletePending(env.DB, domain);
		return jsonResponse({ status: 'accepted', domain, kind: pending.object === PUBLIC_ADDRESS ? 'subscriber' : 'follower' });
	}

	if (section === 'domains' && segments.length === 4 && request.method === 'POST') {
		const decoded = safeDecode(segments[2]);
		if (decoded === null) return textResponse('invalid domain encoding', 400);
		const domain = decoded.toLowerCase().replace(/\.$/, '');
		const action = segments[3];
		if (!domain) return textResponse('invalid domain', 400);
		switch (action) {
			case 'block': {
				// Blocking is a hard rejection: also drop the domain as a
				// receiver and tell follower-style peers to drop the relay.
				const follower = await getFollower(env.DB, domain);
				await setDomainPolicy(env.DB, 'blocked_domains', domain, true);
				await deleteSubscriber(env.DB, domain);
				await deleteFollower(env.DB, domain);
				await deletePending(env.DB, domain);
				if (follower) {
					await enqueueDeliveries(env, config, JSON.stringify(relayUndoFollow(config, follower.actorId)), [follower.inboxUrl]);
				}
				return jsonResponse({ status: 'blocked', domain, receivers_removed: true });
			}
			case 'unblock':
				await setDomainPolicy(env.DB, 'blocked_domains', domain, false);
				return jsonResponse({ status: 'unblocked', domain });
			case 'limit':
				await setDomainPolicy(env.DB, 'limited_domains', domain, true);
				return jsonResponse({ status: 'limited', domain });
			case 'unlimit':
				await setDomainPolicy(env.DB, 'limited_domains', domain, false);
				return jsonResponse({ status: 'unlimited', domain });
			default:
				return notFound();
		}
	}

	if (section === 'settings' && request.method === 'POST') {
		const body = await readJsonBody(request);
		if (!body) return textResponse('invalid JSON body', 400);
		const update: { personOnly?: boolean; manuallyAccept?: boolean } = {};
		if (typeof body.personOnly === 'boolean') update.personOnly = body.personOnly;
		if (typeof body.manuallyAccept === 'boolean') update.manuallyAccept = body.manuallyAccept;
		if (Object.keys(update).length === 0) return textResponse('no supported settings provided', 400);
		await saveRelaySettings(env.DB, update);
		const settings = await loadRelaySettings(env.DB);
		return jsonResponse({ settings: settings ?? update });
	}

	if (section === 'update' && request.method === 'POST') {
		const actor = await buildRelayActor(env, config);
		const result = await enqueueFanOut(env, config, JSON.stringify(relayUpdate(config, actor)), []);
		return jsonResponse({ status: result.ok ? 'queued' : 'rejected', queued: result.queued, reason: result.reason });
	}

	return notFound();
}
