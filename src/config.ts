import type { Env } from './env';

export const RELAY_SOFTWARE_NAME = 'cf-activity-relay';
export const RELAY_SOFTWARE_VERSION = '1.0.0';
export const RELAY_REPOSITORY = 'https://github.com/manalejandro/cf-activity-relay';

export const ACTIVITY_STREAMS_CONTEXT = 'https://www.w3.org/ns/activitystreams';
export const PUBLIC_ADDRESS = 'https://www.w3.org/ns/activitystreams#Public';
export const ACTIVITY_JSON_CONTENT_TYPE = 'application/activity+json';
export const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

/** Maximum accepted body for a remote actor document (2 MiB). */
export const MAX_REMOTE_DOCUMENT_BYTES = 2 * 1024 * 1024;
/** Maximum bytes of a remote error response kept for diagnostics. */
export const MAX_ERROR_BODY_BYTES = 4096;
/** Delivery request timeout. */
export const DELIVERY_TIMEOUT_MS = 5000;
/** Signed remote GET timeout. */
export const FETCH_TIMEOUT_MS = 10000;
/** Remote actor cache TTL in seconds. */
export const ACTOR_CACHE_TTL_SECONDS = 300;
/** Negative actor lookup cache TTL in seconds. */
export const ACTOR_FAILURE_TTL_SECONDS = 60;
/** How long shared fan-out payloads are retained. */
export const PAYLOAD_TTL_SECONDS = 900;
/** Replay-protection retention for RFC 9421 nonces. */
export const NONCE_TTL_SECONDS = 600;
/** Retention for the canonical activity loop guard. */
export const CANONICAL_TTL_SECONDS = 900;
/** Retention for inbound activity de-duplication. */
export const ACTIVITY_DEDUPE_TTL_SECONDS = 86400;
/** Positive RFC 9421 capability evidence lifetime. */
export const CAPABILITY_RFC9421_TTL_SECONDS = 14 * 24 * 3600;
/** Negative (legacy) capability evidence lifetime. */
export const CAPABILITY_LEGACY_TTL_SECONDS = 24 * 3600;
/** Retry delays in seconds applied to delivery attempts 1..5. */
export const DELIVERY_RETRY_DELAYS = [8, 13, 21, 34, 55] as const;
/** Total delivery attempts including the first one. */
export const DELIVERY_MAX_ATTEMPTS = DELIVERY_RETRY_DELAYS.length + 1;

export type PublicAddressPolicy = 'explicit_public_only' | 'public_and_unlisted';
export type SignatureProfile = 'legacy' | 'rfc9421';
export type OutboundProfile = SignatureProfile | 'dual';

export interface RelayConfig {
	/** Bare hostname, for example `relay.example.org`. */
	domain: string;
	/** Canonical base URL without a trailing slash. */
	baseUrl: string;
	/** Relay actor identifier. */
	actorId: string;
	/** Relay actor public key identifier. */
	keyId: string;
	serviceName: string;
	summary: string;
	icon?: string;
	image?: string;
	publicAddressPolicy: PublicAddressPolicy;
	outboundProfile: OutboundProfile;
	personOnly: boolean;
	manuallyAccept: boolean;
	maxActivityBytes: number;
	maxFanoutTargets: number;
	maxQueueJobs: number;
	adminToken?: string;
}

function positiveInt(value: string | undefined, fallback: number, minimum: number): number {
	const parsed = Number.parseInt(value ?? '', 10);
	if (!Number.isFinite(parsed) || parsed < minimum) return fallback;
	return parsed;
}

function booleanValue(value: string | undefined): boolean {
	if (!value) return false;
	return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function normalizeDomain(value: string): string {
	return value.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Loads the immutable relay configuration from the Worker environment.
 * Mutable settings (person-only, manual approval) live in D1 and are applied
 * by `loadRelaySettings` in the data layer.
 */
export function loadConfig(env: Env): RelayConfig {
	const domain = normalizeDomain(env.RELAY_DOMAIN ?? '');
	if (!domain || !/^[a-z0-9.-]+$/.test(domain) || domain.includes('/')) {
		throw new Error('RELAY_DOMAIN is required and must be a bare hostname');
	}
	const baseUrl = `https://${domain}`;
	const policy: PublicAddressPolicy = env.PUBLIC_ADDRESS_DISTRIBUTION_POLICY === 'public_and_unlisted' ? 'public_and_unlisted' : 'explicit_public_only';
	const profile: OutboundProfile =
		env.OUTBOUND_SIGNATURE_PROFILE === 'legacy' || env.OUTBOUND_SIGNATURE_PROFILE === 'rfc9421' ? env.OUTBOUND_SIGNATURE_PROFILE : 'dual';
	return {
		domain,
		baseUrl,
		actorId: `${baseUrl}/actor`,
		keyId: `${baseUrl}/actor#main-key`,
		serviceName: env.RELAY_SERVICENAME?.trim() || 'ActivityPub Relay',
		summary: env.RELAY_SUMMARY?.trim() || '',
		icon: env.RELAY_ICON?.trim() || undefined,
		image: env.RELAY_IMAGE?.trim() || undefined,
		publicAddressPolicy: policy,
		outboundProfile: profile,
		personOnly: booleanValue(env.PERSON_ONLY),
		manuallyAccept: booleanValue(env.MANUALLY_ACCEPT),
		maxActivityBytes: positiveInt(env.MAX_ACTIVITY_BYTES, 1048576, 1024),
		maxFanoutTargets: positiveInt(env.MAX_FANOUT_TARGETS, 5000, 1),
		maxQueueJobs: positiveInt(env.MAX_QUEUE_JOBS, 100000, 1),
		adminToken: env.ADMIN_TOKEN?.trim() || undefined,
	};
}
