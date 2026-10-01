import { ACTIVITY_STREAMS_CONTEXT, type RelayConfig } from '../config';
import type { Env } from '../env';
import { getRelayIdentity } from './identity';

/** Builds the public relay actor document. */
export async function buildRelayActor(env: Env, config: RelayConfig): Promise<Record<string, unknown>> {
	const identity = await getRelayIdentity(env, config);
	const actor: Record<string, unknown> = {
		'@context': [ACTIVITY_STREAMS_CONTEXT, 'https://w3id.org/security/v1'],
		id: config.actorId,
		type: 'Application',
		preferredUsername: 'relay',
		name: config.serviceName,
		inbox: `${config.baseUrl}/inbox`,
		outbox: `${config.baseUrl}/actor/outbox`,
		following: `${config.baseUrl}/actor/following`,
		followers: `${config.baseUrl}/actor/followers`,
		endpoints: { sharedInbox: `${config.baseUrl}/inbox` },
		publicKey: {
			id: config.keyId,
			owner: config.actorId,
			publicKeyPem: identity.publicKeyPem,
		},
	};
	if (config.summary) actor.summary = config.summary;
	if (config.icon) actor.icon = { type: 'Image', url: config.icon };
	if (config.image) actor.image = { type: 'Image', url: config.image };
	return actor;
}

/** Empty, privacy-filtered ordered collection used by the actor endpoints. */
export function emptyOrderedCollection(id: string): Record<string, unknown> {
	return {
		'@context': ACTIVITY_STREAMS_CONTEXT,
		id,
		type: 'OrderedCollection',
		totalItems: 0,
		orderedItems: [],
	};
}

/** WebFinger resource document for `acct:relay@host`. */
export function webfingerDocument(config: RelayConfig): Record<string, unknown> {
	return {
		subject: `acct:relay@${config.domain}`,
		links: [
			{
				rel: 'self',
				type: 'application/activity+json',
				href: config.actorId,
			},
		],
	};
}

/** NodeInfo discovery document. */
export function nodeInfoDiscovery(config: RelayConfig): Record<string, unknown> {
	return {
		links: [
			{
				rel: 'http://nodeinfo.diaspora.software/ns/schema/2.1',
				href: `${config.baseUrl}/nodeinfo/2.1`,
			},
		],
	};
}

/** NodeInfo 2.1 document. `users` counts traditional subscribers. */
export function nodeInfoDocument(config: RelayConfig, subscriberCount: number): Record<string, unknown> {
	return {
		version: '2.1',
		software: {
			name: 'cf-activity-relay',
			version: '1.0.0',
			repository: 'https://github.com/manalejandro/cf-activity-relay',
		},
		protocols: ['activitypub'],
		services: { inbound: [], outbound: [] },
		openRegistrations: true,
		usage: {
			users: {
				total: subscriberCount,
				activeMonth: subscriberCount,
				activeHalfyear: subscriberCount,
			},
		},
		metadata: {},
	};
}
