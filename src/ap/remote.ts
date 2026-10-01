/**
 * Remote actor resolution with signed GET requests and capability learning.
 *
 * Actor documents are cached in KV for five minutes and failures are
 * negatively cached briefly so an unreachable peer cannot cause repeated
 * outbound fetches on every inbound request.
 */
import {
	ACTOR_CACHE_TTL_SECONDS,
	CAPABILITY_LEGACY_TTL_SECONDS,
	CAPABILITY_RFC9421_TTL_SECONDS,
	FETCH_TIMEOUT_MS,
	MAX_REMOTE_DOCUMENT_BYTES,
	type RelayConfig,
	type SignatureProfile,
} from '../config';
import type { Env } from '../env';
import { signLegacyRequest } from '../crypto/legacy';
import { signRfc9421Request } from '../crypto/rfc9421';
import { getCapability, setCapability } from '../store/repo';
import { hostOf, isPrivateHost, normalizeOrigin, parseHttpUrl, stripFragment } from '../utils/domains';
import { discardBody, readTextBounded } from '../utils/http';
import type { RemoteActor } from '../types';
import type { RelayIdentity } from './identity';

const MAX_REDIRECTS = 5;

export interface SignedFetchOptions {
	method: 'GET' | 'POST';
	body?: string | null;
	scope: 'fetch' | 'delivery';
	/** Forces a concrete profile, bypassing capability negotiation. */
	profile?: SignatureProfile;
	accept?: string;
	timeoutMs?: number;
}

export interface SignedFetchResult {
	response: Response;
	profile: SignatureProfile;
}

function shouldFallbackToLegacy(response: Response): boolean {
	if (response.status === 400) return true;
	if (response.status === 401 || response.status === 403) {
		const challenge = response.headers.get('www-authenticate') ?? '';
		return /signature/i.test(challenge);
	}
	return false;
}

async function performSignedFetch(
	config: RelayConfig,
	identity: RelayIdentity,
	url: string,
	profile: SignatureProfile,
	options: SignedFetchOptions,
): Promise<Response> {
	const headers: Record<string, string> = {
		Accept: options.accept ?? 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
	};
	const signing =
		profile === 'legacy'
			? await signLegacyRequest({ method: options.method, url, body: options.body, privateKeyPem: identity.privateKeyPem, keyId: identity.keyId })
			: await signRfc9421Request({ method: options.method, url, body: options.body, privateKeyPem: identity.privateKeyPem, keyId: identity.keyId });
	Object.assign(headers, signing);
	return fetch(url, {
		method: options.method,
		headers,
		body: options.body ?? undefined,
		redirect: 'manual',
		signal: AbortSignal.timeout(options.timeoutMs ?? FETCH_TIMEOUT_MS),
	});
}

/**
 * Performs a signed request using the configured outbound profile policy.
 *
 * `dual` preserves legacy delivery for unknown peers while probing RFC 9421
 * for idempotent fetches, with one legacy fallback after an explicit
 * signature challenge.
 */
export async function signedFetch(env: Env, config: RelayConfig, identity: RelayIdentity, url: string, options: SignedFetchOptions): Promise<SignedFetchResult> {
	const origin = normalizeOrigin(url);
	const capability = origin ? await getCapability(env.DB, origin, options.scope) : null;
	let profile: SignatureProfile;
	if (options.profile) profile = options.profile;
	else if (config.outboundProfile === 'legacy') profile = 'legacy';
	else if (config.outboundProfile === 'rfc9421') profile = 'rfc9421';
	else profile = capability ?? (options.scope === 'fetch' ? 'rfc9421' : 'legacy');

	let response = await performSignedFetch(config, identity, url, profile, options);

	const canLearn = config.outboundProfile === 'dual' && !options.profile;
	if (canLearn && options.scope === 'fetch' && profile === 'rfc9421' && capability === null && shouldFallbackToLegacy(response)) {
		await discardBody(response);
		response = await performSignedFetch(config, identity, url, 'legacy', options);
		if (response.ok && origin) {
			await setCapability(env.DB, origin, 'fetch', 'legacy', CAPABILITY_LEGACY_TTL_SECONDS);
		}
		return { response, profile: 'legacy' };
	}
	if (canLearn && response.ok && origin) {
		await setCapability(env.DB, origin, options.scope, profile, profile === 'rfc9421' ? CAPABILITY_RFC9421_TTL_SECONDS : CAPABILITY_LEGACY_TTL_SECONDS);
	}
	return { response, profile };
}

/**
 * Plans the concrete wire profile for a delivery before it is queued. The
 * chosen profile never changes across retries.
 */
export async function planDeliveryProfile(env: Env, config: RelayConfig, inboxUrl: string): Promise<SignatureProfile> {
	if (config.outboundProfile === 'legacy') return 'legacy';
	if (config.outboundProfile === 'rfc9421') return 'rfc9421';
	const origin = normalizeOrigin(inboxUrl);
	if (origin) {
		const capability = await getCapability(env.DB, origin, 'delivery');
		if (capability) return capability;
	}
	return 'legacy';
}

/** Pure delivery-profile selection using preloaded capability evidence. */
export function profileForDelivery(config: RelayConfig, inboxUrl: string, capabilities: Map<string, SignatureProfile>): SignatureProfile {
	if (config.outboundProfile === 'legacy') return 'legacy';
	if (config.outboundProfile === 'rfc9421') return 'rfc9421';
	const origin = normalizeOrigin(inboxUrl);
	return (origin ? capabilities.get(origin) : undefined) ?? 'legacy';
}

interface ResolvedPublicKey {
	id?: string;
	owner?: string;
	pem: string;
}

/** Extracts the best matching RSA public key from an actor document. */
export function resolvePublicKey(raw: Record<string, unknown>, keyId?: string): ResolvedPublicKey | null {
	const candidates: Array<{ id?: string; owner?: string; pem?: string }> = [];
	const collect = (entry: unknown): void => {
		if (!entry || typeof entry !== 'object') return;
		const object = entry as Record<string, unknown>;
		candidates.push({
			id: typeof object.id === 'string' ? object.id : undefined,
			owner: typeof object.owner === 'string' ? object.owner : undefined,
			pem: typeof object.publicKeyPem === 'string' ? object.publicKeyPem : undefined,
		});
	};
	if (Array.isArray(raw.publicKey)) raw.publicKey.forEach(collect);
	else collect(raw.publicKey);
	if (Array.isArray(raw.assertionMethod)) raw.assertionMethod.forEach(collect);
	else collect(raw.assertionMethod);
	if (typeof raw.publicKeyPem === 'string') {
		candidates.push({ id: typeof raw.id === 'string' ? raw.id : undefined, pem: raw.publicKeyPem });
	}
	const valid = candidates.filter((candidate) => Boolean(candidate.pem));
	if (valid.length === 0) return null;
	if (keyId) {
		const match = valid.find((candidate) => candidate.id === keyId);
		if (match) return { ...match, pem: match.pem as string };
		if (valid.some((candidate) => candidate.id)) return null;
	}
	const first = valid[0];
	return { ...first, pem: first.pem as string };
}

function toRemoteActor(raw: Record<string, unknown>, keyId?: string): RemoteActor | null {
	if (typeof raw.id !== 'string' || !raw.id) return null;
	const endpoints = raw.endpoints && typeof raw.endpoints === 'object' ? (raw.endpoints as Record<string, unknown>) : undefined;
	const sharedInbox = endpoints && typeof endpoints.sharedInbox === 'string' ? endpoints.sharedInbox : undefined;
	const key = resolvePublicKey(raw, keyId);
	return {
		id: raw.id,
		type: typeof raw.type === 'string' ? raw.type : '',
		inbox: typeof raw.inbox === 'string' ? raw.inbox : undefined,
		sharedInbox,
		preferredUsername: typeof raw.preferredUsername === 'string' ? raw.preferredUsername : undefined,
		publicKeyId: key?.id,
		publicKeyPem: key?.pem,
		publicKeyOwner: key?.owner,
		raw,
	};
}

/**
 * Re-resolves the signature key against the cached raw document. Actors that
 * rotate keys publish several keys at once, and the verification keyId is only
 * known per request.
 */
function withResolvedKey(actor: RemoteActor, keyId?: string): RemoteActor {
	if (!keyId) return actor;
	const key = resolvePublicKey(actor.raw, keyId);
	if (!key) return { ...actor, publicKeyId: undefined, publicKeyPem: undefined, publicKeyOwner: undefined };
	return { ...actor, publicKeyId: key.id, publicKeyPem: key.pem, publicKeyOwner: key.owner };
}

/** Resolves an actor document through the cache or a signed remote fetch. */
export async function fetchRemoteActor(env: Env, config: RelayConfig, identity: RelayIdentity, actorUrl: string, keyId?: string): Promise<RemoteActor | null> {
	const cleaned = stripFragment(actorUrl);
	const parsed = parseHttpUrl(cleaned);
	if (!parsed || isPrivateHost(parsed.hostname)) return null;

	const cacheKey = `actor:${cleaned}`;
	const cached = await env.CACHE.get<RemoteActor>(cacheKey, 'json');
	if (cached) return withResolvedKey(cached, keyId);

	const failureKey = `actor-fail:${cleaned}`;
	if (await env.CACHE.get(failureKey)) return null;

	let response: Response;
	try {
		({ response } = await signedFetch(env, config, identity, cleaned, { method: 'GET', scope: 'fetch' }));
	} catch {
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}
	if (!response.ok) {
		await discardBody(response);
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}

	let location = response;
	for (let hop = 0; hop < MAX_REDIRECTS && location.status >= 300 && location.status < 400; hop += 1) {
		const target = location.headers.get('location');
		await discardBody(location);
		if (!target) break;
		let next: URL;
		try {
			next = new URL(target, cleaned);
		} catch {
			break;
		}
		// A redirect must stay on the same host: the actor document host has to
		// match the requested actor host for the signature binding to hold.
		if (hostOf(next.toString()) !== hostOf(cleaned)) {
			await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
			return null;
		}
		({ response: location } = await signedFetch(env, config, identity, next.toString(), { method: 'GET', scope: 'fetch' }));
	}
	if (!location.ok) {
		await discardBody(location);
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}

	const text = await readTextBounded(location, MAX_REMOTE_DOCUMENT_BYTES);
	if (text === null) {
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}
	let raw: Record<string, unknown>;
	try {
		raw = JSON.parse(text) as Record<string, unknown>;
	} catch {
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}
	if (typeof raw.id !== 'string' || hostOf(raw.id) !== hostOf(cleaned)) {
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}
	const actor = toRemoteActor(raw, keyId);
	if (!actor) {
		await env.CACHE.put(failureKey, '1', { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
		return null;
	}
	await env.CACHE.put(cacheKey, JSON.stringify(actor), { expirationTtl: ACTOR_CACHE_TTL_SECONDS });
	return actor;
}

/** Invalidates the cached document for an actor URL. */
export async function invalidateRemoteActor(env: Env, actorUrl: string): Promise<void> {
	await env.CACHE.delete(`actor:${stripFragment(actorUrl)}`);
}

/** Fetches an arbitrary ActivityPub JSON document with a signed GET. */
export async function fetchRemoteJson(env: Env, config: RelayConfig, identity: RelayIdentity, url: string): Promise<Record<string, unknown> | null> {
	const parsed = parseHttpUrl(url);
	if (!parsed || isPrivateHost(parsed.hostname)) return null;
	try {
		const { response } = await signedFetch(env, config, identity, url, { method: 'GET', scope: 'fetch' });
		if (!response.ok) {
			await discardBody(response);
			return null;
		}
		const text = await readTextBounded(response, MAX_REMOTE_DOCUMENT_BYTES);
		if (text === null) return null;
		const raw: unknown = JSON.parse(text);
		if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
		return raw as Record<string, unknown>;
	} catch {
		return null;
	}
}
