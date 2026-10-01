import { ACTIVITY_STREAMS_CONTEXT, PUBLIC_ADDRESS, type RelayConfig } from '../config';
import type { APActivity } from '../types';

/** Generates a stable, relay-scoped activity identifier. */
export function newActivityId(config: RelayConfig): string {
	return `${config.actorId}/activities/${crypto.randomUUID()}`;
}

/**
 * Relay-authored `Announce` wrapper. The relay replaces a publisher transport
 * wrapper with its own signed reference to the canonical object so that the
 * HTTP signer and the JSON actor always agree.
 */
export function relayAnnounce(config: RelayConfig, objectId: string): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: newActivityId(config),
		actor: config.actorId,
		type: 'Announce',
		object: objectId,
		to: [`${config.actorId}/followers`],
	};
}

/** `Accept`/`Reject` reply to an inbound activity. */
export function relayReply(config: RelayConfig, activity: APActivity, type: 'Accept' | 'Reject'): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: newActivityId(config),
		actor: config.actorId,
		type,
		object: activity,
		to: activity.actor ? [activity.actor] : [],
	};
}

/** Reciprocal `Follow` sent to a follower-style subscriber. */
export function relayFollow(config: RelayConfig, remoteActorId: string): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: newActivityId(config),
		actor: config.actorId,
		type: 'Follow',
		object: remoteActorId,
		to: [remoteActorId],
	};
}

/** `Update` containing the current relay actor document. */
export function relayUpdate(config: RelayConfig, actor: Record<string, unknown>): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: newActivityId(config),
		actor: config.actorId,
		type: 'Update',
		object: actor,
		to: [PUBLIC_ADDRESS],
	};
}
