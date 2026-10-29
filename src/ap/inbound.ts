/**
 * Inbound activity processing.
 *
 * Order of operations mirrors the reference Activity-Relay server:
 * bounded body decoding, HTTP signature verification (legacy or RFC 9421),
 * actor/key host binding, public-address policy evaluation, and finally the
 * fan-out state machine.
 */
import { CAPABILITY_RFC9421_TTL_SECONDS, PUBLIC_ADDRESS, type RelayConfig } from '../config';
import type { Env } from '../env';
import { digestHeaderMatches, parseSignatureHeader, verifyLegacySignature } from '../crypto/legacy';
import { parseSignatureInput, verifyRfc9421Signature } from '../crypto/rfc9421';
import { sha256Hex } from '../crypto/digest';
import {
	addFollower,
	addSubscriber,
	bufferPublisher,
	deleteFollower,
	deletePending,
	deleteSubscriber,
	getDomainPolicyFlags,
	getFollower,
	getPeer,
	isSubscriberOrFollower,
	listFollowers,
	listSubscribers,
	loadRelaySettings,
	putPending,
	recordInbound,
	releaseCanonical,
	reserveActivity,
	reserveCanonical,
	reserveNonce,
	setPeerStatus,
	updateFollowerMutual,
} from '../store/repo';
import { asStringArray, hostOf, isDeliverableUrl, isEmbeddedObject, normalizeOrigin, objectId } from '../utils/domains';
import type { APActivity, RelaySettings, RemoteActor } from '../types';
import type { InboundLogEntry } from '../store/repo';
import { relayAnnounce, relayFollow, relayReply, relayUndoFollow } from './builders';
import { enqueueDeliveries, enqueueFanOut, enqueueToFollowers, enqueueToSubscribers } from './fanout';
import type { RelayIdentity } from './identity';
import { allowsPublicAddress, excludesPublicOnlyInCc } from './policy';
import { fetchRemoteActor, fetchRemoteJson, forceRefreshActor, rememberCapability, resolveRemoteActor, type ActorResolution } from './remote';

export interface InboundResponse {
	status: number;
	text?: string;
	/** Short rejection reason for the single operational log line. */
	reason?: string;
	/** Host of the signing key, when one was presented. */
	keyHost?: string;
	/** HTTP status of the signer actor fetch (404/410 mean permanently gone). */
	keyStatus?: number;
}

interface InboundContext {
	env: Env;
	config: RelayConfig;
	identity: RelayIdentity;
	settings: RelaySettings;
	activity: APActivity;
	actor: RemoteActor;
	body: string;
	/**
	 * True when the HTTP signer is an upstream peer relay delivering
	 * third-party content: the JSON actor differs from the signer and the
	 * object must be re-verified against its origin before fan-out.
	 */
	relayed?: boolean;
}

type Verification = { ok: true; ctx: InboundContext } | { ok: false; reason: string; keyHost?: string; keyStatus?: number };

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

/** Best-effort activity shape for the audit trail of rejected requests. */
function parseActivityLoose(body: string): { type?: string; actor?: string; id?: string } {
	try {
		const parsed = JSON.parse(body) as Record<string, unknown>;
		if (!parsed || typeof parsed !== 'object') return {};
		return {
			type: typeof parsed.type === 'string' ? parsed.type : undefined,
			actor: typeof parsed.actor === 'string' ? parsed.actor : undefined,
			id: typeof parsed.id === 'string' ? parsed.id : undefined,
		};
	} catch {
		return {};
	}
}

/**
 * Resolves the signer key, retrying once with a forced refresh. The refresh
 * picks up key rotation and recovers from a stale negative cache entry. The
 * reported status lets callers tell a permanently removed actor (404/410) from
 * a transient failure.
 */
async function resolveSignerActor(env: Env, config: RelayConfig, identity: RelayIdentity, keyId: string): Promise<ActorResolution> {
	const first = await resolveRemoteActor(env, config, identity, keyId, keyId);
	if (first.actor?.publicKeyPem) return first;
	const refreshed = await forceRefreshActor(env, config, identity, keyId, keyId);
	if (refreshed.actor?.publicKeyPem) return refreshed;
	// Prefer a real HTTP status over a cached miss.
	return refreshed.status > 0 ? refreshed : first;
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
): Promise<Verification> {
	const parsed = parseSignatureHeader(headers['signature'] ?? '');
	if (!parsed?.keyId) return { ok: false, reason: 'signature-missing' };
	const keyHost = hostOf(parsed.keyId);
	if (!headers['digest']) return { ok: false, reason: 'digest-missing', keyHost };
	if (!(await digestHeaderMatches(headers['digest'], body))) return { ok: false, reason: 'digest-mismatch', keyHost };

	const resolution = await resolveSignerActor(env, config, identity, parsed.keyId);
	let signerActor = resolution.actor;
	if (!signerActor?.publicKeyPem) return { ok: false, reason: 'key-unresolved', keyHost, keyStatus: resolution.status };
	let verification = await verifyLegacySignature({ method: request.method, url, headers, body, publicKeyPem: signerActor.publicKeyPem });
	if (!verification.ok) {
		const refreshed = await forceRefreshActor(env, config, identity, parsed.keyId, parsed.keyId);
		if (refreshed.actor?.publicKeyPem && refreshed.actor.publicKeyPem !== signerActor.publicKeyPem) {
			verification = await verifyLegacySignature({ method: request.method, url, headers, body, publicKeyPem: refreshed.actor.publicKeyPem });
			if (verification.ok) signerActor = refreshed.actor;
		}
		if (!verification.ok) return { ok: false, reason: 'signature-invalid', keyHost };
	}

	const activity = parseActivity(body);
	if (!activity?.actor) return { ok: false, reason: 'malformed-activity', keyHost };
	const actorDomain = hostOf(activity.actor);
	if (!actorDomain) return { ok: false, reason: 'malformed-activity', keyHost };
	if (hostOf(parsed.keyId) !== hostOf(signerActor.id)) return { ok: false, reason: 'actor-binding', keyHost };
	if (signerActor.publicKeyOwner && hostOf(signerActor.publicKeyOwner) !== hostOf(signerActor.id)) return { ok: false, reason: 'actor-binding', keyHost };

	// Relay-to-relay: an upstream peer signs deliveries of third-party content.
	// The signer/actor split is only accepted from active peers; the object is
	// re-verified against its origin before any fan-out.
	if (hostOf(signerActor.id) !== actorDomain) {
		if (!(await isActivePeer(env.DB, hostOf(signerActor.id)))) return { ok: false, reason: 'actor-binding', keyHost };
		const settings = await loadSettings(env, config);
		return { ok: true, ctx: { env, config, identity, settings, activity, actor: signerActor, body, relayed: true } };
	}

	const actor = activity.actor === signerActor.id ? signerActor : await fetchRemoteActor(env, config, identity, activity.actor);
	if (!actor || hostOf(actor.id) !== actorDomain) return { ok: false, reason: 'actor-unresolved', keyHost };

	const settings = await loadSettings(env, config);
	return { ok: true, ctx: { env, config, identity, settings, activity, actor, body } };
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
): Promise<Verification> {
	const members = parseSignatureInput(headers['signature-input'] ?? '');
	if (members.length === 0) return { ok: false, reason: 'signature-missing' };
	// Prefer `activitypub`-tagged members; bound the number of candidates so a
	// multi-member header cannot amplify actor fetches.
	const ordered = [...members.filter((member) => member.params.tag === 'activitypub'), ...members.filter((member) => member.params.tag !== 'activitypub')].slice(0, 2);

	let reason = 'signature-missing';
	let keyHost: string | undefined;
	let keyStatus: number | undefined;
	for (const member of ordered) {
		const keyId = member.params.keyid;
		if (!keyId) continue;
		keyHost = hostOf(keyId);

		const resolution = await resolveSignerActor(env, config, identity, keyId);
		let signerActor = resolution.actor;
		if (!signerActor?.publicKeyPem) {
			reason = 'key-unresolved';
			keyStatus = resolution.status;
			continue;
		}
		const verify = (publicKeyPem: string) =>
			verifyRfc9421Signature({
				method: request.method,
				url,
				headers,
				body,
				publicKeyPem,
				expectedAuthority: config.domain,
				label: member.label,
			});
		let verification = await verify(signerActor.publicKeyPem);
		if (!verification.ok) {
			const refreshed = await forceRefreshActor(env, config, identity, keyId, keyId);
			if (refreshed.actor?.publicKeyPem && refreshed.actor.publicKeyPem !== signerActor.publicKeyPem) {
				signerActor = refreshed.actor;
				verification = await verify(refreshed.actor.publicKeyPem);
			}
			if (!verification.ok) {
				reason = 'signature-invalid';
				continue;
			}
		}
		if (!verification.keyId) {
			reason = 'signature-invalid';
			continue;
		}

		const activity = parseActivity(body);
		if (!activity?.actor) return { ok: false, reason: 'malformed-activity', keyHost };
		if (signerActor.publicKeyId !== verification.keyId) {
			reason = 'actor-binding';
			continue;
		}
		// Relay-to-relay: upstream peers sign third-party content. Only active
		// peers may present a signer/actor split; the object is re-verified
		// against its origin before any fan-out.
		const relayed = signerActor.id !== activity.actor;
		if (relayed && !(await isActivePeer(env.DB, hostOf(signerActor.id)))) {
			reason = 'actor-binding';
			continue;
		}
		if (signerActor.publicKeyOwner !== (relayed ? signerActor.id : activity.actor)) {
			reason = 'actor-binding';
			continue;
		}

		// Reserve the nonce only after both the signature and the digest succeeded.
		if (verification.nonce) {
			const nonceHash = await sha256Hex(`${verification.keyId}\u0000${verification.nonce}`);
			if (!(await reserveNonce(env.DB, nonceHash))) {
				reason = 'replay';
				continue;
			}
		}

		// A peer that signs inbound requests with RFC 9421 can very likely
		// verify it too: remember the evidence so dual-mode fan-out plans
		// RFC 9421 deliveries for that origin (with a bounded legacy fallback).
		const origin = normalizeOrigin(signerActor.id);
		if (origin) {
			try {
				await rememberCapability(env, origin, 'delivery', 'rfc9421', CAPABILITY_RFC9421_TTL_SECONDS);
			} catch (error) {
				console.warn('unable to record delivery capability', { origin, error: error instanceof Error ? error.message : String(error) });
			}
		}

		const settings = await loadSettings(env, config);
		return { ok: true, ctx: { env, config, identity, settings, activity, actor: signerActor, body, relayed } };
	}
	return { ok: false, reason, keyHost, keyStatus };
}

async function loadSettings(env: Env, config: RelayConfig): Promise<RelaySettings> {
	const stored = await loadRelaySettings(env.DB);
	return stored ?? { personOnly: config.personOnly, manuallyAccept: config.manuallyAccept };
}

/** True when the domain is an upstream peer relay with an accepted subscription. */
async function isActivePeer(db: D1Database, domain: string): Promise<boolean> {
	const peer = await getPeer(db, domain);
	return peer?.status === 'active';
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

/**
 * True when the actor is a server-level actor entitled to subscribe:
 * `Application`/`Service` actors or the historical `/relay` and `/friendica`
 * server-actor paths. A personal account following the relay would otherwise
 * receive every relayed public activity in its home timeline.
 */
function isServerActor(actor: RemoteActor): boolean {
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
	const flags = await getDomainPolicyFlags(ctx.env.DB, domain);
	if (flags.blocked || flags.limited) return false;
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
	const flags = await getDomainPolicyFlags(ctx.env.DB, domain);
	if (flags.blocked) return { ok: false, error: `${domain} is blocked` };
	if (!(await isActorAbleToRelay(ctx, ctx.actor))) return { ok: true };
	await bufferPublisher(ctx.env.DB, {
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
	const flags = await getDomainPolicyFlags(ctx.env.DB, sourceDomain);
	if (flags.blocked) return { status: 401, text: `${sourceDomain} is blocked`, reason: 'blocked' };
	if (!(await isActorAbleToRelay(ctx, ctx.actor))) return { status: 202 };

	const publisher = await recordPublisherActivity(ctx);
	if (!publisher.ok) return { status: 401, text: publisher.error, reason: 'blocked' };

	// Duplicate deliveries of the same activity must not fan out twice. The
	// de-duplication key binds the activity id to its signer so a hostile
	// publisher cannot reserve somebody else's identifiers.
	if (ctx.activity.id) {
		const dedupeKey = await sha256Hex(`${ctx.actor.id}\u0000${ctx.activity.id}`);
		if (!(await reserveActivity(ctx.env.DB, dedupeKey))) return { status: 202 };
	}

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
	const flags = await getDomainPolicyFlags(ctx.env.DB, sourceDomain);
	if (flags.blocked) return { status: 401, text: `${sourceDomain} is blocked`, reason: 'blocked' };
	if (!(await isActorAbleToRelay(ctx, ctx.actor))) return { status: 202 };
	const embeddedId = objectId(ctx.activity.object);
	if (!embeddedId) return { status: 202 };
	const publisher = await recordPublisherActivity(ctx);
	if (!publisher.ok) return { status: 401, text: publisher.error, reason: 'blocked' };
	await enqueueFanOut(ctx.env, ctx.config, JSON.stringify(relayAnnounce(ctx.config, embeddedId)), [sourceDomain]);
	return { status: 202 };
}

async function executePublicAnnounce(ctx: InboundContext): Promise<InboundResponse> {
	if (shouldFanOutPublicAnnounce(ctx.activity)) return executeEmbeddedAnnounce(ctx);
	const sourceDomain = hostOf(ctx.actor.id);
	const flags = await getDomainPolicyFlags(ctx.env.DB, sourceDomain);
	if (flags.blocked) return { status: 401, text: `${sourceDomain} is blocked`, reason: 'blocked' };
	// Peers may address their wrappers to the public collection: chain them
	// through the referenced-Announce path (origin re-verification included).
	if (typeof ctx.activity.object === 'string' && (await isActivePeer(ctx.env.DB, sourceDomain))) {
		return executeRelayAddressedAnnounce(ctx);
	}
	const publisher = await recordPublisherActivity(ctx);
	if (!publisher.ok) return { status: 401, text: publisher.error, reason: 'blocked' };
	return { status: 202 };
}

/**
 * Fetches a referenced object with bounded retries. Relays announce objects
 * milliseconds after publication, and origin edge caches can answer 404 until
 * the object propagates; a couple of short retries recover most of them.
 */
async function fetchReferencedObject(
	env: Env,
	config: RelayConfig,
	identity: RelayIdentity,
	url: string,
): Promise<Record<string, unknown> | null> {
	const delays = [1000, 2000];
	for (let attempt = 0; ; attempt += 1) {
		const doc = await fetchRemoteJson(env, config, identity, url);
		if (doc) return doc;
		if (attempt >= delays.length) return null;
		await new Promise((resolve) => setTimeout(resolve, delays[attempt]));
	}
}

async function executeRelayAddressedAnnounce(ctx: InboundContext): Promise<InboundResponse> {
	const sourceDomain = hostOf(ctx.actor.id);
	if (!(await isSubscriberOrFollower(ctx.env.DB, sourceDomain)) && !(await isActivePeer(ctx.env.DB, sourceDomain))) {
		return { status: 401, text: 'to use the relay service, please follow in advance', reason: 'not-subscribed' };
	}
	const referencedUrl = objectId(ctx.activity.object);
	if (!referencedUrl) return { status: 202 };
	const referenced = await fetchReferencedObject(ctx.env, ctx.config, ctx.identity, referencedUrl);
	if (!referenced || typeof referenced.id !== 'string') {
		// Unfetchable objects are dropped, not rejected: a 4xx would only make
		// the sender retry content whose origin is gone or unreachable.
		return { status: 202, reason: 'referenced-unfetchable' };
	}
	// Servers that serve the object itself (Note) instead of the wrapping
	// Create attribute it with `attributedTo` rather than `actor`.
	const referencedActor = typeof referenced.actor === 'string' ? referenced.actor : asStringArray(referenced.attributedTo)[0];
	if (!referencedActor) return { status: 202, reason: 'referenced-unfetchable' };
	// Never amplify content the origin did not address to the public
	// audience: relaying an unlisted or restricted object would punch through
	// the public-address distribution policy and the origin's intent.
	const referencedTo = asStringArray(referenced.to);
	const referencedCc = asStringArray(referenced.cc);
	if (!allowsPublicAddress(referencedTo, referencedCc, ctx.config.publicAddressPolicy)) {
		return { status: 202, reason: 'referenced-not-public' };
	}
	const canonicalHash = await sha256Hex(referenced.id);
	if (!(await reserveCanonical(ctx.env.DB, canonicalHash))) return { status: 202, reason: 'duplicate' };

	const originDomain = hostOf(referencedActor);
	if (!originDomain) return { status: 202, reason: 'referenced-bad-origin' };
	const originFlags = await getDomainPolicyFlags(ctx.env.DB, originDomain);
	if (originFlags.blocked) return { status: 401, text: `${originDomain} is blocked`, reason: 'blocked' };
	const originActor = await fetchRemoteActor(ctx.env, ctx.config, ctx.identity, referencedActor);
	if (!originActor) return { status: 202, reason: 'origin-actor-unresolved' };
	if (!(await isActorAbleToRelay(ctx, originActor))) return { status: 202, reason: 'origin-not-relayable' };
	await bufferPublisher(ctx.env.DB, {
		domain: originDomain,
		actorId: originActor.id,
		inboxUrl: originActor.sharedInbox ?? originActor.inbox ?? null,
		activityId: referenced.id,
		activityType: typeof referenced.type === 'string' ? referenced.type : 'Announce',
	});
	const result = await enqueueFanOut(ctx.env, ctx.config, JSON.stringify(relayAnnounce(ctx.config, referenced.id)), [sourceDomain, originDomain]);
	if (!result.ok) {
		await releaseCanonical(ctx.env.DB, canonicalHash);
		return { status: 401, text: `fan-out rejected: ${result.reason}`, reason: 'fanout' };
	}
	return { status: 202, reason: 'chained' };
}

/**
 * Content delivered by an upstream peer relay under the peer's HTTP signature
 * (signer ≠ JSON actor). Nothing is trusted from the peer: the referenced
 * object is fetched from its origin, its attribution and public audience are
 * verified, and only then is it re-announced to this relay's receivers.
 *
 * Two de-duplication layers keep relay chains loop-free: a 24 h per-object
 * reservation (survives the canonical guard window) and the 15 min canonical
 * guard shared with the referenced-Announce path.
 */
async function executePeerRelayed(ctx: InboundContext): Promise<InboundResponse> {
	const peerDomain = hostOf(ctx.actor.id);
	const peerFlags = await getDomainPolicyFlags(ctx.env.DB, peerDomain);
	if (peerFlags.blocked) return { status: 401, text: `${peerDomain} is blocked`, reason: 'blocked' };

	// Delete/Move notices reference objects that are gone or rewritten at the
	// origin: there is nothing to fetch. An intact Linked-Data proof lets
	// traditional subscribers verify the original author themselves, so those
	// notices are forwarded verbatim; unsigned ones cannot be attributed.
	if (ctx.activity.type === 'Delete' || ctx.activity.type === 'Move') {
		if (!hasLinkedDataSignature(ctx.body)) {
			return { status: 202, reason: ctx.activity.type === 'Delete' ? 'delete-unverifiable' : 'move-unverifiable' };
		}
		await enqueueToSubscribers(ctx.env, ctx.config, ctx.body, [peerDomain, hostOf(ctx.activity.actor ?? '')]);
		return { status: 202, reason: ctx.activity.type === 'Delete' ? 'forwarded-delete' : 'forwarded-move' };
	}

	const referencedId = objectId(ctx.activity.object);
	if (!referencedId) return { status: 202 };
	const fetched = await fetchReferencedObject(ctx.env, ctx.config, ctx.identity, referencedId);
	if (!fetched || typeof fetched.id !== 'string') return { status: 202, reason: 'peer-object-unfetchable' };

	// Unwrap Create/Update transport wrappers to the canonical object.
	let canonical: Record<string, unknown> = fetched;
	if ((fetched.type === 'Create' || fetched.type === 'Update') && isEmbeddedObject(fetched.object)) {
		const inner = fetched.object as Record<string, unknown>;
		if (typeof inner.id === 'string') canonical = inner;
	}
	const canonicalId = typeof canonical.id === 'string' ? canonical.id : fetched.id;
	const originDomain = hostOf(canonicalId);
	if (!originDomain) return { status: 202 };

	// Attribution: the object must belong to the domain that hosts it.
	const attribution = asStringArray(canonical.attributedTo)[0] ?? asStringArray(canonical.actor)[0] ?? '';
	if (!attribution || hostOf(attribution) !== originDomain) return { status: 202, reason: 'attribution-mismatch' };

	// Audience: only genuinely public content travels through the chain.
	const activityTo = asStringArray(fetched.to);
	const activityCc = asStringArray(fetched.cc);
	const to = activityTo.length > 0 ? activityTo : asStringArray(canonical.to);
	const cc = activityCc.length > 0 ? activityCc : asStringArray(canonical.cc);
	if (!allowsPublicAddress(to, cc, ctx.config.publicAddressPolicy)) return { status: 202, reason: 'referenced-not-public' };

	const originFlags = await getDomainPolicyFlags(ctx.env.DB, originDomain);
	if (originFlags.blocked) return { status: 401, text: `${originDomain} is blocked`, reason: 'blocked' };

	// Loop protection: one re-announcement per canonical object per window.
	const objectKey = await sha256Hex(`peer-object\u0000${canonicalId}`);
	if (!(await reserveActivity(ctx.env.DB, objectKey))) return { status: 202, reason: 'duplicate' };
	const canonicalHash = await sha256Hex(canonicalId);
	if (!(await reserveCanonical(ctx.env.DB, canonicalHash))) return { status: 202, reason: 'duplicate' };

	const originActor = await fetchRemoteActor(ctx.env, ctx.config, ctx.identity, attribution);
	if (!originActor) return { status: 202, reason: 'origin-actor-unresolved' };
	if (!(await isActorAbleToRelay(ctx, originActor))) return { status: 202, reason: 'origin-not-relayable' };
	await bufferPublisher(ctx.env.DB, {
		domain: originDomain,
		actorId: originActor.id,
		inboxUrl: originActor.sharedInbox ?? originActor.inbox ?? null,
		activityId: canonicalId,
		activityType: typeof canonical.type === 'string' ? canonical.type : 'Note',
	});

	const preserveOriginal = hasLinkedDataSignature(ctx.body);
	const announce = JSON.stringify(relayAnnounce(ctx.config, canonicalId));
	let result: { ok: boolean; queued: number; reason?: 'fanout_limit' | 'queue_full' | 'broker' };
	if (preserveOriginal) {
		// The intact Linked-Data proof lets traditional subscribers verify the
		// original author themselves; followers get the relay wrapper.
		await enqueueToSubscribers(ctx.env, ctx.config, ctx.body, [peerDomain, originDomain]);
		const subscribers = await listSubscribers(ctx.env.DB);
		result = await enqueueToFollowers(ctx.env, ctx.config, announce, [peerDomain, originDomain, ...subscribers.map((subscriber) => subscriber.domain)]);
	} else {
		result = await enqueueFanOut(ctx.env, ctx.config, announce, [peerDomain, originDomain]);
	}
	if (!result.ok) {
		await releaseCanonical(ctx.env.DB, canonicalHash);
		return { status: 401, text: `fan-out rejected: ${result.reason}`, reason: 'fanout' };
	}
	return { status: 202, reason: 'chained' };
}

async function executeFollowing(ctx: InboundContext): Promise<InboundResponse> {
	const actorDomain = hostOf(ctx.actor.id);
	const inbox = ctx.actor.inbox ?? ctx.actor.sharedInbox;
	const flags = await getDomainPolicyFlags(ctx.env.DB, actorDomain);
	if (flags.blocked) {
		await sendReply(ctx, 'Reject', inbox);
		return { status: 202, reason: 'blocked' };
	}
	// A relay must never subscribe to itself: a self-referential receiver would
	// re-enter the fan-out path and could loop on relay-authored wrappers.
	if (actorDomain === ctx.config.domain) {
		await sendReply(ctx, 'Reject', inbox);
		return { status: 202, reason: 'self' };
	}
	const objectValues = asStringArray(ctx.activity.object);
	if (objectValues.includes(PUBLIC_ADDRESS)) {
		// Traditional subscriptions also come from server actors: a personal
		// account sending Follow(Public) would pull the whole firehose into a
		// home timeline.
		if (!isServerActor(ctx.actor)) {
			await sendReply(ctx, 'Reject', inbox);
			return { status: 202, reason: 'not-a-server-actor' };
		}
		const subscriberInbox = ctx.actor.sharedInbox ?? ctx.actor.inbox;
		if (!subscriberInbox || !isDeliverableUrl(subscriberInbox)) {
			await sendReply(ctx, 'Reject', inbox);
			return { status: 202, reason: 'no-usable-inbox' };
		}
		if (ctx.settings.manuallyAccept) {
			await putPending(ctx.env.DB, {
				domain: actorDomain,
				inboxUrl: subscriberInbox,
				activityId: ctx.activity.id ?? '',
				type: 'Follow',
				actor: ctx.actor.id,
				object: PUBLIC_ADDRESS,
				createdAt: new Date().toISOString(),
			});
			return { status: 202, reason: 'pending' };
		}
		await sendReply(ctx, 'Accept', inbox);
		await addSubscriber(ctx.env.DB, {
			domain: actorDomain,
			inboxUrl: subscriberInbox,
			activityId: ctx.activity.id ?? '',
			actorId: ctx.actor.id,
		});
		return { status: 202, reason: 'subscribed' };
	}
	if (objectValues.includes(ctx.config.actorId)) {
		if (!isServerActor(ctx.actor)) {
			// Only server actors subscribe by following the relay actor. A
			// personal account following it would otherwise receive every
			// relayed public activity in its home timeline.
			await sendReply(ctx, 'Reject', inbox);
			return { status: 202, reason: 'not-a-server-actor' };
		}
		const followerInbox = ctx.actor.inbox ?? ctx.actor.sharedInbox;
		if (!followerInbox || !isDeliverableUrl(followerInbox)) {
			await sendReply(ctx, 'Reject', inbox);
			return { status: 202, reason: 'no-usable-inbox' };
		}
		if (ctx.settings.manuallyAccept) {
			await putPending(ctx.env.DB, {
				domain: actorDomain,
				inboxUrl: followerInbox,
				activityId: ctx.activity.id ?? '',
				type: 'Follow',
				actor: ctx.actor.id,
				object: ctx.config.actorId,
				createdAt: new Date().toISOString(),
			});
			return { status: 202, reason: 'pending' };
		}
		await addFollower(ctx.env.DB, {
			domain: actorDomain,
			inboxUrl: followerInbox,
			activityId: ctx.activity.id ?? '',
			actorId: ctx.actor.id,
		});
		await sendReply(ctx, 'Accept', inbox);
		// Never re-follow a domain we already subscribe to as a peer: the
		// reciprocal Follow would otherwise ping-pong forever between relays.
		const peer = await getPeer(ctx.env.DB, actorDomain);
		if (!flags.limited && !peer) {
			await sendActivity(ctx, ctx.actor.inbox, JSON.stringify(relayFollow(ctx.config, ctx.actor.id)));
		}
		return { status: 202, reason: 'followed' };
	}
	await sendReply(ctx, 'Reject', inbox);
	return { status: 202, reason: 'unsupported-follow' };
}

async function executeUnfollowing(ctx: InboundContext, innerFollow: Record<string, unknown>): Promise<InboundResponse> {
	const actorDomain = hostOf(ctx.actor.id);
	// The inner Follow must belong to the verified signer; stale or forged
	// Undo payloads must never mutate subscription state.
	if (typeof innerFollow.actor === 'string' && innerFollow.actor !== ctx.actor.id) {
		await sendReply(ctx, 'Reject', ctx.actor.inbox ?? ctx.actor.sharedInbox);
		return { status: 202, reason: 'undo-actor-mismatch' };
	}
	const objectValues = asStringArray(innerFollow.object);
	if (objectValues.includes(PUBLIC_ADDRESS)) {
		await deleteSubscriber(ctx.env.DB, actorDomain);
		await deletePending(ctx.env.DB, actorDomain);
		return { status: 202, reason: 'unsubscribed' };
	}
	if (objectValues.includes(ctx.config.actorId) && isServerActor(ctx.actor)) {
		const follower = await getFollower(ctx.env.DB, actorDomain);
		await deleteFollower(ctx.env.DB, actorDomain);
		await deletePending(ctx.env.DB, actorDomain);
		// Tell the peer so it can drop the relay from its own following list.
		if (follower) await sendActivity(ctx, follower.inboxUrl, JSON.stringify(relayUndoFollow(ctx.config, follower.actorId)));
		return { status: 202, reason: 'unfollowed' };
	}
	await sendReply(ctx, 'Reject', ctx.actor.inbox ?? ctx.actor.sharedInbox);
	return { status: 202, reason: 'unsupported-undo' };
}

/** Unwraps an `Undo{Follow}`; returns null when the inner activity is not a Follow. */
function unwrapInnerFollow(object: unknown): Record<string, unknown> | null {
	if (!isEmbeddedObject(object) || object.type !== 'Follow') return null;
	return object;
}

async function finalizeMutuallyFollow(ctx: InboundContext): Promise<InboundResponse> {
	const inner = ctx.activity.object;
	const innerId = objectId(inner);
	const actorDomain = hostOf(ctx.actor.id);
	// Response to one of our outbound peer-subscription Follows. Checked
	// first: a peer Accept embeds our Follow whose object is the peer actor,
	// which looks exactly like a mutual-follow response.
	const peer = await getPeer(ctx.env.DB, actorDomain);
	if (peer && innerId && innerId === peer.followId) {
		await setPeerStatus(ctx.env.DB, actorDomain, ctx.activity.type === 'Accept' ? 'active' : 'rejected');
		if (ctx.activity.type === 'Accept') await updateFollowerMutual(ctx.env.DB, actorDomain, true);
		return { status: 202, reason: ctx.activity.type === 'Accept' ? 'peer-active' : 'peer-rejected' };
	}
	if (!isEmbeddedObject(inner)) return { status: 202 };
	if (inner.type !== 'Follow') return { status: 202 };
	if (inner.actor !== ctx.config.actorId) return { status: 202 };
	if (inner.object === ctx.actor.id) {
		const follower = await getFollower(ctx.env.DB, actorDomain);
		if (!follower) return { status: 202 };
		await updateFollowerMutual(ctx.env.DB, actorDomain, ctx.activity.type === 'Accept');
		return { status: 202 };
	}
	// Peers that reference our Follow by value instead of by id.
	if (peer && (inner.object === peer.actorId || (peer.style === 'traditional' && inner.object === PUBLIC_ADDRESS))) {
		await setPeerStatus(ctx.env.DB, actorDomain, ctx.activity.type === 'Accept' ? 'active' : 'rejected');
		return { status: 202, reason: ctx.activity.type === 'Accept' ? 'peer-active' : 'peer-rejected' };
	}
	return { status: 202 };
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/** True when the audience addresses the relay or one of its followers. */
async function addressesRelay(db: D1Database, config: RelayConfig, to: string[], cc: string[]): Promise<boolean> {
	if (to.includes(config.actorId) || cc.includes(config.actorId)) return true;
	return (await isToMyFollower(db, to)) || (await isToMyFollower(db, cc));
}

async function dispatchInbound(ctx: InboundContext): Promise<InboundResponse> {
	const to = asStringArray(ctx.activity.to);
	const cc = asStringArray(ctx.activity.cc);
	const policy = ctx.config.publicAddressPolicy;

	// Content arriving through an upstream peer relay: re-verify at the origin
	// and re-announce; subscription traffic from the peer follows the normal
	// paths below (there the signer is the actor).
	if (ctx.relayed) {
		switch (ctx.activity.type) {
			case 'Create':
			case 'Update':
			case 'Delete':
			case 'Move':
			case 'Announce':
				return executePeerRelayed(ctx);
			default:
				return { status: 202 };
		}
	}

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

	// Evaluated lazily: the public path (the overwhelming majority of relay
	// traffic) never needs the follower-collection lookups.
	if (await addressesRelay(ctx.env.DB, ctx.config, to, cc)) {
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

	// Upstream peers address their Announce wrappers to their own audience or
	// to this relay: chain them after re-verifying the referenced object.
	if (ctx.activity.type === 'Announce' && (await isActivePeer(ctx.env.DB, hostOf(ctx.actor.id)))) {
		return executeRelayAddressedAnnounce(ctx);
	}

	if (excludesPublicOnlyInCc(to, cc, policy)) {
		if (['Create', 'Update', 'Delete', 'Move', 'Announce'].includes(ctx.activity.type)) {
			const publisher = await recordPublisherActivity(ctx);
			if (!publisher.ok) return { status: 401, text: publisher.error, reason: 'blocked' };
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

/**
 * The D1 audit trail persists rejections and operationally interesting
 * outcomes. Plain successes (chained fan-outs, ordinary 202s) are emitted to
 * Workers Logs only: at firehose volume one INSERT per inbox POST was among
 * the largest sources of written rows.
 */
async function recordInboundEvent(env: Env, entry: InboundLogEntry): Promise<void> {
	if (entry.status >= 400 || (entry.reason && entry.reason !== 'chained')) {
		await recordInbound(env.DB, entry);
		return;
	}
	console.log('inbound accepted', { type: entry.type, domain: entry.actorDomain, activityId: entry.activityId, status: entry.status });
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
	const verification = usesRfc9421
		? await verifyRfc9421(env, config, identity, request, url.toString(), headers, body)
		: await verifyLegacy(env, config, identity, request, url.toString(), headers, body);
	if (!verification.ok) {
		const partial = parseActivityLoose(body);
		// Account deletion notices are signed by keys that are already gone: the
		// actor document returns 404/410, so nobody can verify them. A relay
		// keeps no account state, so acknowledge the notice without acting on it
		// instead of making the sender retry it forever.
		if (verification.reason === 'key-unresolved' && partial.type === 'Delete' && (verification.keyStatus === 404 || verification.keyStatus === 410)) {
			await recordInbound(env.DB, {
				at: Math.floor(Date.now() / 1000),
				type: 'Delete',
				actorDomain: hostOf(partial.actor ?? '') || verification.keyHost || '',
				activityId: partial.id ?? null,
				status: 202,
				reason: 'unverifiable-delete',
			});
			return { status: 202, reason: 'unverifiable-delete', keyHost: verification.keyHost, keyStatus: verification.keyStatus };
		}
		await recordInbound(env.DB, {
			at: Math.floor(Date.now() / 1000),
			type: partial.type ?? 'unknown',
			actorDomain: hostOf(partial.actor ?? '') || verification.keyHost || '',
			activityId: partial.id ?? null,
			status: 400,
			reason: verification.reason,
		});
		return { status: 400, reason: verification.reason, keyHost: verification.keyHost, keyStatus: verification.keyStatus };
	}

	const result = await dispatchInbound(verification.ctx);
	await recordInboundEvent(env, {
		at: Math.floor(Date.now() / 1000),
		type: verification.ctx.activity.type,
		actorDomain: hostOf(verification.ctx.actor.id),
		activityId: verification.ctx.activity.id ?? null,
		status: result.status,
		reason: result.reason ?? null,
	});
	return result;
}
