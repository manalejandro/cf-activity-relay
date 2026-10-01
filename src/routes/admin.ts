/**
 * Small administrative API replacing the reference CLI.
 *
 * Enabled only when `ADMIN_TOKEN` is configured; every request must present
 * `Authorization: Bearer <ADMIN_TOKEN>`.
 */
import { PUBLIC_ADDRESS, type RelayConfig } from '../config';
import type { Env } from '../env';
import { buildRelayActor } from '../ap/actor';
import { relayFollow, relayReply, relayUpdate } from '../ap/builders';
import { enqueueDeliveries, enqueueFanOut } from '../ap/fanout';
import {
	addFollower,
	addSubscriber,
	deletePending,
	getPending,
	isLimited,
	listBlockedDomains,
	listFollowers,
	listLimitedDomains,
	listPending,
	listPublishers,
	listSubscribers,
	loadRelaySettings,
	saveRelaySettings,
	setDomainPolicy,
} from '../store/repo';
import type { APActivity } from '../types';
import { jsonResponse, notFound, textResponse } from '../utils/http';

function unauthorized(): Response {
	return textResponse('unauthorized', 401, { headers: { 'WWW-Authenticate': 'Bearer' } });
}

async function readJsonBody(request: Request): Promise<Record<string, unknown> | null> {
	try {
		const text = await request.text();
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
	if (request.headers.get('authorization') !== `Bearer ${config.adminToken}`) return unauthorized();

	const segments = url.pathname.split('/').filter(Boolean);
	// segments[0] === 'admin'
	const section = segments[1];

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
		const domain = decodeURIComponent(segments[2]);
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
		const domain = decodeURIComponent(segments[2]).toLowerCase().replace(/\.$/, '');
		const action = segments[3];
		if (!domain) return textResponse('invalid domain', 400);
		switch (action) {
			case 'block':
				await setDomainPolicy(env.DB, 'blocked_domains', domain, true);
				return jsonResponse({ status: 'blocked', domain });
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
