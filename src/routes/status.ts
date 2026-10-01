import { RELAY_REPOSITORY, RELAY_SOFTWARE_NAME, RELAY_SOFTWARE_VERSION, type RelayConfig } from '../config';
import type { Env } from '../env';
import { listFollowers, listPublishers, listReceiverHealth, listSubscribers, loadRelaySettings } from '../store/repo';
import { jsonResponse, methodNotAllowed } from '../utils/http';

function sortedUnique(values: string[]): string[] {
	return [...new Set(values.filter(Boolean))].sort();
}

/**
 * `GET|HEAD /status.json` — public relay status, schema version 5.
 *
 * The document deliberately excludes inbox URLs, actor IDs, blocked-domain
 * lists and queue internals.
 */
export async function handleStatus(env: Env, config: RelayConfig, request: Request): Promise<Response> {
	if (request.method !== 'GET' && request.method !== 'HEAD') return methodNotAllowed('GET, HEAD');
	const [subscribers, followers, publishers, settings] = await Promise.all([
		listSubscribers(env.DB),
		listFollowers(env.DB),
		listPublishers(env.DB),
		loadRelaySettings(env.DB),
	]);
	const personOnly = settings?.personOnly ?? config.personOnly;
	const manuallyAccept = settings?.manuallyAccept ?? config.manuallyAccept;

	const subscriberDomains = sortedUnique(subscribers.map((subscriber) => subscriber.domain));
	const receivingDomains = sortedUnique([...subscriberDomains, ...followers.map((follower) => follower.domain)]);
	const publisherDomains = sortedUnique(publishers.map((publisher) => publisher.domain));
	const connectedDomains = sortedUnique([...receivingDomains, ...publisherDomains]);
	const health = await listReceiverHealth(env.DB, receivingDomains);
	const subscriberSet = new Set(subscriberDomains);
	const receivingSet = new Set(receivingDomains);

	const body: Record<string, unknown> = {
		schema_version: 5,
		status: 'ok',
		name: config.serviceName,
		domain: config.domain,
		registration: manuallyAccept ? 'approval_required' : 'open',
		manual_approval: manuallyAccept,
		person_only: personOnly,
		public_address_distribution_policy: config.publicAddressPolicy,
		public_address_distribution_label: config.publicAddressPolicy === 'explicit_public_only' ? 'Public posts only' : 'Public and unlisted posts',
		endpoints: {
			inbox: `${config.baseUrl}/inbox`,
			actor: config.actorId,
		},
		connected_instances: {
			count: connectedDomains.length,
			domains: connectedDomains,
		},
		receiving_instances: {
			count: receivingDomains.length,
			domains: receivingDomains,
			entries: receivingDomains.map((domain) => {
				const entry = health.get(domain);
				const record: Record<string, unknown> = {
					domain,
					consecutive_failures: entry?.consecutiveFailures ?? 0,
					total_successes: entry?.totalSuccesses ?? 0,
					total_failures: entry?.totalFailures ?? 0,
				};
				if (entry?.lastSuccessAt) record.last_success_at = entry.lastSuccessAt;
				if (entry?.lastFailureAt) record.last_failure_at = entry.lastFailureAt;
				return record;
			}),
		},
		publishers: {
			count: publisherDomains.length,
			entries: publishers.map((publisher) => ({
				domain: publisher.domain,
				first_seen: publisher.firstSeen,
				last_seen: publisher.lastSeen,
				last_activity_type: publisher.lastActivityType,
				activity_count: publisher.activityCount,
				subscribed: subscriberSet.has(publisher.domain),
				receives_relay: receivingSet.has(publisher.domain),
			})),
		},
		software: {
			name: RELAY_SOFTWARE_NAME,
			version: RELAY_SOFTWARE_VERSION,
			repository: RELAY_REPOSITORY,
		},
	};

	if (request.method === 'HEAD') {
		return new Response(null, { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=30', 'X-Content-Type-Options': 'nosniff' } });
	}
	return jsonResponse(body, { headers: { 'Cache-Control': 'public, max-age=30' } });
}
