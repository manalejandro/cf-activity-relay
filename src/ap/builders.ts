import { ACTIVITY_STREAMS_CONTEXT, PUBLIC_ADDRESS, type RelayConfig } from '../config';
import type { APActivity } from '../types';
import { hostOf } from '../utils/domains';

/** Generates a stable, relay-scoped activity identifier. */
export function newActivityId(config: RelayConfig): string {
	return `${config.actorId}/activities/${crypto.randomUUID()}`;
}

/**
 * Relay-authored `Announce` wrapper. The relay replaces a publisher transport
 * wrapper with its own signed reference to the canonical object so that the
 * HTTP signer and the JSON actor always agree.
 *
 * `published` and both audience fields are always present: some receivers
 * reject Announces without `published` (FEP-ae0c) and Akkoma's announce
 * validator requires `to` and `cc` to exist.
 */
export function relayAnnounce(config: RelayConfig, objectId: string): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: newActivityId(config),
		actor: config.actorId,
		type: 'Announce',
		object: objectId,
		published: new Date().toISOString(),
		to: [`${config.actorId}/followers`],
		cc: [],
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
		id: reciprocalFollowId(config, remoteActorId),
		actor: config.actorId,
		type: 'Follow',
		object: remoteActorId,
		to: [remoteActorId],
	};
}

/**
 * Stable identifier of the reciprocal Follow for a domain. Deterministic so
 * the relay can later `Undo` it (unsubscribe, block) without storing it.
 */
export function reciprocalFollowId(config: RelayConfig, remoteActorId: string): string {
	return `${config.actorId}/follows/${hostOf(remoteActorId) || remoteActorId}`;
}

/** `Undo` of the relay's reciprocal Follow, sent when a receiver is dropped. */
export function relayUndoFollow(config: RelayConfig, remoteActorId: string, followObject: string = remoteActorId): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: newActivityId(config),
		actor: config.actorId,
		type: 'Undo',
		object: {
			'@context': [ACTIVITY_STREAMS_CONTEXT],
			id: reciprocalFollowId(config, remoteActorId),
			type: 'Follow',
			actor: config.actorId,
			object: followObject,
		},
		to: [remoteActorId],
	};
}

/**
 * Outbound subscription Follow to an upstream peer relay. The identifier is
 * the deterministic per-domain Follow id so retries, the reciprocal handshake
 * and the later `Undo` all reference the same logical activity.
 */
export function peerFollow(config: RelayConfig, peerActorId: string, style: 'follower' | 'traditional'): APActivity {
	return {
		'@context': [ACTIVITY_STREAMS_CONTEXT],
		id: reciprocalFollowId(config, peerActorId),
		actor: config.actorId,
		type: 'Follow',
		object: style === 'traditional' ? PUBLIC_ADDRESS : peerActorId,
		to: [peerActorId],
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
		published: new Date().toISOString(),
		to: [PUBLIC_ADDRESS],
		cc: [],
	};
}
