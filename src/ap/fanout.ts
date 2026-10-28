/**
 * Fan-out planning and queue admission.
 *
 * Targets are de-duplicated per normalized domain with the traditional
 * subscriber route preferred, the publishing source is always excluded, and
 * queue admission is bounded by `MAX_FANOUT_TARGETS` and `MAX_QUEUE_JOBS`.
 */
import { type RelayConfig } from '../config';
import type { DeliveryMessage, Env } from '../env';
import type { Receiver } from '../types';
import { isDeliverableUrl, normalizeDomain } from '../utils/domains';
import { countPendingJobs, createPayload, deletePayload, listBlockedDomains, listCapabilities, listLimitedDomains, listReceivers } from '../store/repo';
import { profileForDelivery } from './remote';

export interface FanOutResult {
	ok: boolean;
	queued: number;
	reason?: 'fanout_limit' | 'queue_full' | 'broker';
}

/**
 * Removes a trailing dot, lowercases, and de-duplicates delivery targets.
 * Domains in `silenced` (blocked or limited by moderation) are skipped: a
 * block/limit must stop the relay from delivering to that domain too.
 */
export function selectTargets(receivers: Receiver[], excludeDomains: string[], silenced: Set<string> = new Set()): Receiver[] {
	const excluded = new Set(excludeDomains.map((domain) => normalizeDomain(domain)).filter(Boolean));
	const seen = new Set<string>();
	const targets: Receiver[] = [];
	for (const receiver of receivers) {
		const domain = normalizeDomain(receiver.domain);
		if (!domain || excluded.has(domain) || seen.has(domain)) continue;
		if (silenced.has(domain)) continue;
		if (!isDeliverableUrl(receiver.inboxUrl)) continue;
		seen.add(domain);
		targets.push({ ...receiver, domain });
	}
	return targets;
}

/** Blocked + limited domains as a single lookup set for fan-out filtering. */
export async function silencedDomains(env: Env): Promise<Set<string>> {
	const [blocked, limited] = await Promise.all([listBlockedDomains(env.DB), listLimitedDomains(env.DB)]);
	return new Set([...blocked, ...limited].map((domain) => normalizeDomain(domain)).filter(Boolean));
}

/**
 * Stores a shared payload and enqueues one delivery task per destination.
 * The payload is deleted when the queue rejects the whole batch so a broker
 * failure cannot leak state.
 */
export async function enqueueDeliveries(env: Env, config: RelayConfig, body: string, inboxUrls: string[]): Promise<FanOutResult> {
	const unique = [...new Set(inboxUrls.filter((inbox) => isDeliverableUrl(inbox)))];
	if (unique.length === 0) return { ok: true, queued: 0 };
	if (unique.length > config.maxFanoutTargets) return { ok: false, queued: 0, reason: 'fanout_limit' };

	const pending = await countPendingJobs(env.DB);
	if (pending + unique.length > config.maxQueueJobs) return { ok: false, queued: 0, reason: 'queue_full' };

	const capabilities = await listCapabilities(env.DB, 'delivery');
	const payloadId = crypto.randomUUID();
	const messages: DeliveryMessage[] = unique.map((inboxUrl) => ({
		v: 1,
		inboxUrl,
		payloadId,
		profile: profileForDelivery(config, inboxUrl, capabilities),
	}));

	try {
		await createPayload(env.DB, payloadId, body, messages.length);
	} catch (error) {
		console.error('fan-out payload store failed', { payloadId, error: error instanceof Error ? error.message : String(error) });
		return { ok: false, queued: 0, reason: 'broker' };
	}
	try {
		for (let index = 0; index < messages.length; index += 100) {
			const chunk = messages.slice(index, index + 100).map((message) => ({ body: message }));
			try {
				await env.DELIVERY_QUEUE.sendBatch(chunk);
			} catch {
				// One bounded retry before giving up on the whole payload.
				await env.DELIVERY_QUEUE.sendBatch(chunk);
			}
		}
	} catch (error) {
		await deletePayload(env.DB, payloadId);
		console.error('fan-out enqueue failed', { payloadId, error: error instanceof Error ? error.message : String(error) });
		return { ok: false, queued: 0, reason: 'broker' };
	}
	return { ok: true, queued: messages.length };
}

/** Fans a body out to every registered receiver, excluding source domains. */
export async function enqueueFanOut(env: Env, config: RelayConfig, body: string, excludeDomains: string[]): Promise<FanOutResult> {
	const [receivers, silenced] = await Promise.all([listReceivers(env.DB), silencedDomains(env)]);
	const targets = selectTargets(receivers, excludeDomains, silenced);
	return enqueueDeliveries(
		env,
		config,
		body,
		targets.map((target) => target.inboxUrl),
	);
}

/** Fans a body out to the traditional subscribers only. */
export async function enqueueToSubscribers(env: Env, config: RelayConfig, body: string, excludeDomains: string[]): Promise<FanOutResult> {
	const [receivers, silenced] = await Promise.all([listReceivers(env.DB), silencedDomains(env)]);
	const targets = selectTargets(
		receivers.filter((receiver) => receiver.kind === 'subscriber'),
		excludeDomains,
		silenced,
	);
	return enqueueDeliveries(
		env,
		config,
		body,
		targets.map((target) => target.inboxUrl),
	);
}

/** Fans a body out to follower-style receivers, excluding the given domains. */
export async function enqueueToFollowers(env: Env, config: RelayConfig, body: string, excludeDomains: string[]): Promise<FanOutResult> {
	const [receivers, silenced] = await Promise.all([listReceivers(env.DB), silencedDomains(env)]);
	const targets = selectTargets(
		receivers.filter((receiver) => receiver.kind === 'follower'),
		excludeDomains,
		silenced,
	);
	return enqueueDeliveries(
		env,
		config,
		body,
		targets.map((target) => target.inboxUrl),
	);
}
