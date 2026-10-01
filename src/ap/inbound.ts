/**
 * Inbound activity processing.
 *
 * Order of operations mirrors the reference Activity-Relay server:
 * bounded body decoding, HTTP signature verification (legacy or RFC 9421),
 * actor/key host binding, public-address policy evaluation, and finally the
 * fan-out state machine.
 */
import { PUBLIC_ADDRESS, type RelayConfig } from '../config';
import type { Env } from '../env';
import { digestHeaderMatches, parseSignatureHeader, verifyLegacySignature } from '../crypto/legacy';
import { parseSignatureInput, verifyRfc9421Signature } from '../crypto/rfc9421';
import { sha256Hex } from '../crypto/digest';
import {
	addFollower,
	addSubscriber,
	deleteFollower,
	deletePending,
	deleteSubscriber,
	getFollower,
	isBlocked,
	isLimited,
	isSubscriberOrFollower,
	listFollowers,
	listSubscribers,
	loadRelaySettings,
	putPending,
	recordPublisher,
	releaseCanonical,
	reserveActivity,
	reserveCanonical,
	reserveNonce,
	updateFollowerMutual,
} from '../store/repo';
import { asStringArray, hostOf, isEmbeddedObject, objectId } from '../utils/domains';
import type { APActivity, RelaySettings, RemoteActor } from '../types';
import { relayAnnounce, relayFollow, relayReply } from './builders';
import { enqueueDeliveries, enqueueFanOut, enqueueToFollowers, enqueueToSubscribers } from './fanout';
import type { RelayIdentity } from './identity';
import { allowsPublicAddress, excludesPublicOnlyInCc } from './policy';
import { fetchRemoteActor, fetchRemoteJson } from './remote';

export interface InboundResponse {
	status: number;
	text?: string;
}

interface InboundContext {
	env: Env;
	config: RelayConfig;
	identity: RelayIdentity;
	settings: RelaySettings;
	activity: APActivity;
	actor: RemoteActor;
	body: string;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

function parseActivity(body: string): APActivity | null {
	try {
		const parsed = JSON.parse(body) as APActivity;
		if (!parsed || typeof parsed !== 'object') return null;
		if (typeof parsed.type !== 'string' || !parsed.type) return null;
		if (typeof parsed.actor !== 'string' || !parsed.actor) return null;
		return parsed;
	} catch {
		return null;
	}
}

/** Legacy draft-cavage verification with actor/key host binding. */
async function verifyLegacy(
	env: Env,
	config: RelayConfig,
	identity: RelayIdentity,
	request: Request,
	url: string,
	headers: Record<string, string>,
	body: string,
): Promise<InboundContext | null> {
	const fail = (reason: string): null => {
		console.warn('legacy verification rejected', { reason });
		return null;
	};
	const parsed = parseSignatureHeader(headers['signature'] ?? '');
	if (!parsed?.keyId) return fail('missing keyId');
	if (!headers['digest']) return fail('missing Digest header');
	if (!(await digestHeaderMatches(headers['digest'], body))) return fail('Digest header does not match the body');

	const signerActor = await fetchRemoteActor(env, config, identity, parsed.keyId, parsed.keyId);
	if (!signerActor?.publicKeyPem) return fail('unable to resolve the signer public key');
	const verification = await verifyLegacySignature({ method: request.method, url, headers, body, publicKeyPem: signerActor.publicKeyPem });
	if (!verification.ok) return fail(verification.error ?? 'signature verification failed');

	const activity = parseActivity(body);
	if (!activity?.actor) return fail('malformed activity');
	const actorDomain = hostOf(activity.actor);
	if (!actorDomain) return fail('activity actor has no hostname');
	if (hostOf(parsed.keyId) !== actorDomain) return fail('signature key host does not match the activity actor');
	if (hostOf(signerActor.id) !== actorDomain) return fail('signer actor host does not match the activity actor');
	if (signerActor.publicKeyOwner && hostOf(signerActor.publicKeyOwner) !== actorDomain) return fail('public key owner host does not match the activity actor');

	const actor = activity.actor === signerActor.id ? signerActor : await fetchRemoteActor(env, config, identity, activity.actor);
	if (!actor || hostOf(actor.id) !== actorDomain) return fail('unable to resolve the activity actor document');

	const settings = await loadSettings(env, config);
	return { env, config, identity, settings, activity, actor, body };
}

/** RFC 9421 verification with nonce replay protection. */
async function verifyRfc9421(
	env: Env,
	config: RelayConfig,
	identity: RelayIdentity,
	request: Request,
	url: string,
	headers: Record<string, string>,
	body: string,
): Promise<InboundContext | null> {
	const fail = (reason: string): null => {
		console.warn('rfc9421 verification rejected', { reason });
		return null;
	};
	const members = parseSignatureInput(headers['signature-input'] ?? '');
	const tagged = members.filter((member) => member.params.tag === 'activitypub');
	if (tagged.length !== 1) return fail('expected exactly one activitypub signature member');
	const keyId = tagged[0].params.keyid;
	if (!keyId) return fail('missing keyid');

	const signerActor = await fetchRemoteActor(env, config, identity, keyId, keyId);
	if (!signerActor?.publicKeyPem) return fail('unable to resolve the signer public key');
	const verification = await verifyRfc9421Signature({
		method: request.method,
		url,
		headers,
		body,
		publicKeyPem: signerActor.publicKeyPem,
		expectedAuthority: config.domain,
	});
	if (!verification.ok || !verification.keyId || !verification.nonce) return fail(verification.error ?? 'signature verification failed');

	const activity = parseActivity(body);
	if (!activity?.actor) return fail('malformed activity');
	if (signerActor.publicKeyId !== verification.keyId) return fail('public key id does not match the signature keyid');
	if (signerActor.publicKeyOwner !== activity.actor) return fail('public key owner does not match the activity actor');
	if (signerActor.id !== activity.actor) return fail('signer actor does not match the activity actor');

	// Reserve the nonce only after both the signature and the digest succeeded.
	const nonceHash = await sha256Hex(`${verification.keyId}\u0000${verification.nonce}`);
	if (!(await reserveNonce(env.DB, nonceHash))) return fail('replayed signature nonce');

	const settings = await loadSettings(env, config);
	return { env, config, identity, settings, activity, actor: signerActor, body };
}

async function loadSettings(env: Env, config: RelayConfig): Promise<RelaySettings> {
	const stored = await loadRelaySettings(env.DB);
	return stored ?? { personOnly: config.personOnly, manuallyAccept: config.manuallyAccept };
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

function isActorAbleToBeFollower(actor: RemoteActor): boolean {
	if (actor.type === 'Application' || actor.type === 'Service') return true;
	try {
		const path = new URL(actor.id).pathname.replace(/\/$/, '');
		return path === '/relay' || path === '/friendica';
	} catch {
		return false;
	}
}

async function isActorAbleToRelay(ctx: InboundContext, actor: RemoteActor): Promise<boolean> {
	const domain = hostOf(actor.id);
	if (!domain) return false;
	if (await isBlocked(ctx.env.DB, domain)) return false;
	if (await isLimited(ctx.env.DB, domain)) return false;
	if (ctx.settings.personOnly && actor.type !== 'Person') return false;
	return true;
}

async function isToMyFollower(db: D1Database, entries: string[]): Promise<boolean> {
	const candidates = entries.filter((entry) => entry.endsWith('/followers'));
	if (candidates.length === 0) return false;
	const followers = await listFollowers(db);
	const actorIds = new Set(followers.map((follower) => follower.actorId));
	return candidates.some((entry) => actorIds.has(entry.slice(0, -'/followers'.length)));
}

/** Shape-only Mastodon Linked-Data signature detection. */
function hasLinkedDataSignature(body: string): boolean {
	try {
		const envelope = JSON.parse(body) as { signature?: unknown };
		if (!envelope.signature || typeof envelope.signature !== 'object') return false;
		const signature = envelope.signature as Record<string, unknown>;
		return (
			signature.type === 'RsaSignature2017' &&
			typeof signature.creator === 'string' &&
			signature.creator.trim() !== '' &&
			typeof signature.created === 'string' &&
			signature.created.trim() !== '' &&
			typeof signature.signatureValue === 'string' &&
			signature.signatureValue.trim() !== ''
		);
	} catch {
		return false;
	}
}

function shouldFanOutPublicAnnounce(activity: APActivity): boolean {
	if (activity.type !== 'Announce' || !isEmbeddedObject(activity.object)) return false;
	const embeddedId = objectId(activity.object);
	if (!embeddedId) return false;
	const actorDomain = hostOf(activity.actor ?? '');
	const objectDomain = hostOf(embeddedId);
	return Boolean(actorDomain) && actorDomain === objectDomain;
}

// ---------------------------------------------------------------------------
// Delivery helpers for relay replies
// ---------------------------------------------------------------------------

async function sendActivity(ctx: InboundContext, inboxUrl: string | undefined, body: string): Promise<void> {
	if (!inboxUrl) return;
	const result = await enqueueDeliveries(ctx.env, ctx.config, body, [inboxUrl]);
	if (!result.ok) console.warn('unable to queue relay reply', { inbox: inboxUrl, reason: result.reason });
}

async function sendReply(ctx: InboundContext, type: 'Accept' | 'Reject', inboxUrl: string | undefined): Promise<void> {
	await sendActivity(ctx, inboxUrl, JSON.stringify(relayReply(ctx.config, ctx.activity, type)));
}

// ---------------------------------------------------------------------------
// Activity handlers
// ---------------------------------------------------------------------------

async function recordPublisherActivity(ctx: InboundContext): Promise<{ ok: boolean; error?: string }> {
	const domain = hostOf(ctx.actor.id);
	if (!domain) return { ok: false, error: 'activity actor has an invalid ID' };
	if (await isBlocked(ctx.env.DB, domain)) return { ok: false, error: `${domain} is blocked` };
	if (!(await isActorAbleToRelay(ctx, ctx.actor))) return { ok: true };
	await recordPublisher(ctx.env.DB, {
		domain,
		actorId: ctx.actor.id,
		inboxUrl: ctx.actor.sharedInbox ?? ctx.actor.inbox ?? null,
		activityId: ctx.activity.id ?? null,
		activityType: ctx.activity.type,
	});
	return { ok: true };
}

async function executeRelayActivity(ctx: InboundContext): Promise<InboundResponse> {
	const sourceDomain = hostOf(ctx.actor.id);
	if (await isBlocked(ctx.env.DB, sourceDomain)) return { status: 401, text: `${sourceDomain} is blocked` };
	if (!(await isActorAbleToRelay(ctx, ctx.actor))) return { status: 202 };

	const publisher = await recordPublisherActivity(ctx);
	if (!publisher.ok) return { status: 401, text: publisher.error };

	// Duplicate deliveries of the same activity must not fan out twice.
	if (ctx.activity.id && !(await reserveActivity(ctx.env.DB, ctx.activity.id))) return { status: 202 };

	const preserveOriginal = hasLinkedDataSignature(ctx.body);
	if (preserveOriginal) {
		await enqueueToSubscribers(ctx.env, ctx.config, ctx.body, [sourceDomain]);
	}

	const announcedObject = objectId(ctx.activity.object);
	if (!announcedObject) {
		// An unsigned source activity cannot be forwarded under the relay's
		// HTTP signature because signer and JSON actor would differ.
		return { status: 202 };
	}
	const announce = JSON.stringify(relayAnnounce(ctx.config, announcedObject));
	if (preserveOriginal) {
		const subscribers = await listSubscribers(ctx.env.DB);
		await enqueueToFollowers(ctx.env, ctx.config, announce, [sourceDomain, ...subscribers.map((subscriber) => subscriber.domain)]);
	} else {
		await enqueueFanOut(ctx.env, ctx.config, announce, [sourceDomain]);
	}
	return { status: 202 };
}

async function executeEmbeddedAnnounce(ctx: InboundContext): Promise<InboundResponse> {
	const sourceDomain = hostOf(ctx.actor.id);
	if (await isBlocked(ctx.env.DB, sourceDomain)) return { status: 401, text: `${sourceDomain} is blocked` };
	if (!(await isActorAbleToRelay(ctx, ctx.actor))) return { status: 202 };
	const embeddedId = objectId(ctx.activity.object);
	if (!embeddedId) return { status: 202 };
	const publisher = await recordPublisherActivity(ctx);
	if (!publisher.ok) return { status: 401, text: publisher.error };
	await enqueueFanOut(ctx.env, ctx.config, JSON.stringify(relayAnnounce(ctx.config, embeddedId)), [sourceDomain]);
	return { status: 202 };
}

async function executePublicAnnounce(ctx: InboundContext): Promise<InboundResponse> {
	if (shouldFanOutPublicAnnounce(ctx.activity)) return executeEmbeddedAnnounce(ctx);
	const sourceDomain = hostOf(ctx.actor.id);
	if (await isBlocked(ctx.env.DB, sourceDomain)) return { status: 401, text: `${sourceDomain} is blocked` };
	const publisher = await recordPublisherActivity(ctx);
	if (!publisher.ok) return { status: 401, text: publisher.error };
	return { status: 202 };
}

async function executeRelayAddressedAnnounce(ctx: InboundContext): Promise<InboundResponse> {
	const sourceDomain = hostOf(ctx.actor.id);
	if (!(await isSubscriberOrFollower(ctx.env.DB, sourceDomain))) {
		return { status: 401, text: 'to use the relay service, please follow in advance' };
	}
	const referencedUrl = objectId(ctx.activity.object);
	if (!referencedUrl) return { status: 202 };
	const referenced = await fetchRemoteJson(ctx.env, ctx.config, ctx.identity, referencedUrl);
	if (!referenced || typeof referenced.id !== 'string' || typeof referenced.actor !== 'string') {
		return { status: 400, text: 'unable to fetch the announced activity' };
	}
	const canonicalHash = await sha256Hex(referenced.id);
	if (!(await reserveCanonical(ctx.env.DB, canonicalHash))) return { status: 202 };

	const originDomain = hostOf(referenced.actor);
	if (!originDomain) return { status: 202 };
	if (await isBlocked(ctx.env.DB, originDomain)) return { status: 401, text: `${originDomain} is blocked` };
	const originActor = await fetchRemoteActor(ctx.env, ctx.config, ctx.identity, referenced.actor);
	if (!originActor || !(await isActorAbleToRelay(ctx, originActor))) return { status: 202 };
	await recordPublisher(ctx.env.DB, {
		domain: originDomain,
		actorId: originActor.id,
		inboxUrl: originActor.sharedInbox ?? originActor.inbox ?? null,
		activityId: referenced.id,
		activityType: typeof referenced.type === 'string' ? referenced.type : 'Announce',
	});
	const result = await enqueueFanOut(ctx.env, ctx.config, JSON.stringify(relayAnnounce(ctx.config, referenced.id)), [sourceDomain, originDomain]);
	if (!result.ok) {
		await releaseCanonical(ctx.env.DB, canonicalHash);
		return { status: 401, text: `fan-out rejected: ${result.reason}` };
	}
	return { status: 202 };
}

async function executeFollowing(ctx: InboundContext): Promise<InboundResponse> {
	const actorDomain = hostOf(ctx.actor.id);
	const inbox = ctx.actor.inbox ?? ctx.actor.sharedInbox;
	if (await isBlocked(ctx.env.DB, actorDomain)) {
		await sendReply(ctx, 'Reject', inbox);
		return { status: 202 };
	}
	// A relay must never subscribe to itself: a self-referential receiver would
	// re-enter the fan-out path and could loop on relay-authored wrappers.
	if (actorDomain === ctx.config.domain) {
		await sendReply(ctx, 'Reject', inbox);
		return { status: 202 };
	}
	const objectValues = asStringArray(ctx.activity.object);
	if (objectValues.includes(PUBLIC_ADDRESS)) {
		if (ctx.settings.manuallyAccept) {
			await putPending(ctx.env.DB, {
				domain: actorDomain,
				inboxUrl: ctx.actor.sharedInbox ?? ctx.actor.inbox ?? '',
				activityId: ctx.activity.id ?? '',
				type: 'Follow',
				actor: ctx.actor.id,
				object: PUBLIC_ADDRESS,
				createdAt: new Date().toISOString(),
			});
			return { status: 202 };
		}
		await sendReply(ctx, 'Accept', inbox);
		await addSubscriber(ctx.env.DB, {
			domain: actorDomain,
			inboxUrl: ctx.actor.sharedInbox ?? ctx.actor.inbox ?? '',
			activityId: ctx.activity.id ?? '',
			actorId: ctx.actor.id,
		});
		return { status: 202 };
	}
	if (objectValues.includes(ctx.config.actorId)) {
		if (!isActorAbleToBeFollower(ctx.actor)) {
			await sendReply(ctx, 'Reject', inbox);
			return { status: 202 };
		}
		if (ctx.settings.manuallyAccept) {
			await putPending(ctx.env.DB, {
				domain: actorDomain,
				inboxUrl: ctx.actor.inbox ?? ctx.actor.sharedInbox ?? '',
				activityId: ctx.activity.id ?? '',
				type: 'Follow',
				actor: ctx.actor.id,
				object: ctx.config.actorId,
				createdAt: new Date().toISOString(),
			});
			return { status: 202 };
		}
		await addFollower(ctx.env.DB, {
			domain: actorDomain,
			inboxUrl: ctx.actor.inbox ?? ctx.actor.sharedInbox ?? '',
			activityId: ctx.activity.id ?? '',
			actorId: ctx.actor.id,
		});
		await sendReply(ctx, 'Accept', inbox);
		if (!(await isLimited(ctx.env.DB, actorDomain))) {
			await sendActivity(ctx, ctx.actor.inbox, JSON.stringify(relayFollow(ctx.config, ctx.actor.id)));
		}
		return { status: 202 };
	}
	await sendReply(ctx, 'Reject', inbox);
	return { status: 202 };
}

async function executeUnfollowing(ctx: InboundContext, innerFollow: Record<string, unknown>): Promise<InboundResponse> {
	const actorDomain = hostOf(ctx.actor.id);
	const objectValues = asStringArray(innerFollow.object);
	if (objectValues.includes(PUBLIC_ADDRESS)) {
		await deleteSubscriber(ctx.env.DB, actorDomain);
		await deletePending(ctx.env.DB, actorDomain);
		return { status: 202 };
	}
	if (objectValues.includes(ctx.config.actorId) && isActorAbleToBeFollower(ctx.actor)) {
		await deleteFollower(ctx.env.DB, actorDomain);
		await deletePending(ctx.env.DB, actorDomain);
		return { status: 202 };
	}
	await sendReply(ctx, 'Reject', ctx.actor.inbox ?? ctx.actor.sharedInbox);
	return { status: 202 };
}

/** Unwraps an `Undo{Follow}`; returns null when the inner activity is not a Follow. */
function unwrapInnerFollow(object: unknown): Record<string, unknown> | null {
	if (!isEmbeddedObject(object) || object.type !== 'Follow') return null;
	return object;
}

async function finalizeMutuallyFollow(ctx: InboundContext): Promise<InboundResponse> {
	const inner = ctx.activity.object;
	if (!isEmbeddedObject(inner)) return { status: 202 };
	if (inner.type !== 'Follow') return { status: 202 };
	if (inner.actor !== ctx.config.actorId) return { status: 202 };
	if (inner.object !== ctx.actor.id) return { status: 202 };
	const actorDomain = hostOf(ctx.actor.id);
	const follower = await getFollower(ctx.env.DB, actorDomain);
	if (!follower) return { status: 202 };
	await updateFollowerMutual(ctx.env.DB, actorDomain, ctx.activity.type === 'Accept');
	return { status: 202 };
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

async function dispatchInbound(ctx: InboundContext): Promise<InboundResponse> {
	const to = asStringArray(ctx.activity.to);
	const cc = asStringArray(ctx.activity.cc);
	const policy = ctx.config.publicAddressPolicy;
	const addressesRelay =
		to.includes(ctx.config.actorId) || cc.includes(ctx.config.actorId) || (await isToMyFollower(ctx.env.DB, to)) || (await isToMyFollower(ctx.env.DB, cc));

	if (allowsPublicAddress(to, cc, policy)) {
		switch (ctx.activity.type) {
			case 'Create':
			case 'Update':
			case 'Delete':
			case 'Move':
				return executeRelayActivity(ctx);
			case 'Announce':
				return executePublicAnnounce(ctx);
			default:
				return { status: 202 };
		}
	}

	if (addressesRelay) {
		switch (ctx.activity.type) {
			case 'Follow':
				return executeFollowing(ctx);
			case 'Undo': {
				const innerFollow = unwrapInnerFollow(ctx.activity.object);
				return innerFollow ? executeUnfollowing(ctx, innerFollow) : { status: 202 };
			}
			case 'Accept':
			case 'Reject':
				return finalizeMutuallyFollow(ctx);
			case 'Announce':
				return executeRelayAddressedAnnounce(ctx);
			default:
				return { status: 202 };
		}
	}

	if (excludesPublicOnlyInCc(to, cc, policy)) {
		if (['Create', 'Update', 'Delete', 'Move', 'Announce'].includes(ctx.activity.type)) {
			const publisher = await recordPublisherActivity(ctx);
			if (!publisher.ok) return { status: 401, text: publisher.error };
		}
		return { status: 202 };
	}

	switch (ctx.activity.type) {
		case 'Follow':
			return executeFollowing(ctx);
		case 'Undo': {
			const innerFollow = unwrapInnerFollow(ctx.activity.object);
			return innerFollow ? executeUnfollowing(ctx, innerFollow) : { status: 202 };
		}
		default:
			return { status: 202 };
	}
}

/** Verifies and processes an inbound POST to `/inbox`. */
export async function processInboundActivity(env: Env, config: RelayConfig, identity: RelayIdentity, request: Request, body: string): Promise<InboundResponse> {
	const url = new URL(request.url);
	url.hash = '';
	const headers: Record<string, string> = {};
	request.headers.forEach((value, key) => {
		headers[key.toLowerCase()] = value;
	});
	headers['host'] = url.host;

	const usesRfc9421 = request.headers.has('signature-input');
	const ctx = usesRfc9421
		? await verifyRfc9421(env, config, identity, request, url.toString(), headers, body)
		: await verifyLegacy(env, config, identity, request, url.toString(), headers, body);
	if (!ctx) return { status: 400 };
	return dispatchInbound(ctx);
}
