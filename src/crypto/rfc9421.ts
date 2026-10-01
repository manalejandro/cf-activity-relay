/**
 * RFC 9421 HTTP Message Signatures and RFC 9530 Content-Digest.
 *
 * The relay verifies the `activitypub` signature tag exactly as specified by
 * the Activity-Relay profile: `rsa-v1_5-sha256`, a nonce, a `created`
 * timestamp, and the full POST component set. Outbound requests use the same
 * profile with one concrete signature per operation.
 */
import { importPrivateKey, importPublicKey, RSA_ALGORITHM } from './keys';
import { randomToken, sha256Base64, timingSafeEqual, utf8 } from './digest';

export const RFC9421_SIGNATURE_LABEL = 'activitypub';
export const RFC9421_SIGNATURE_TAG = 'activitypub';
export const RFC9421_ALGORITHM = 'rsa-v1_5-sha256';

/**
 * Components every inbound POST signature must cover.
 *
 * This is the Mastodon verification rule set (`SignedRequest`): the derived
 * `@method` and `@target-uri` components plus `content-digest` for POST. The
 * Fediverse RFC 9421 profile also signs `@authority`, `content-type` and
 * `date`, but those are optional here so that senders which emit the minimal
 * component set are still accepted. Every component a sender *does* cover is
 * always included in the signing base.
 */
export const RFC9421_REQUIRED_POST_COMPONENTS = ['@method', '@target-uri', 'content-digest'] as const;

const MAX_CREATED_AGE_SECONDS = 300;
const MAX_CREATED_SKEW_SECONDS = 30;

export interface ParsedSignatureMember {
	label: string;
	components: string[];
	params: Record<string, string>;
	/** Exact member value after `label=`, required verbatim for `@signature-params`. */
	paramsString: string;
}

/** Splits a comma separated header into members, respecting quotes. */
function splitMembers(value: string): string[] {
	const members: string[] = [];
	let current = '';
	let inQuotes = false;
	for (const char of value) {
		if (char === '"') inQuotes = !inQuotes;
		if (char === ',' && !inQuotes) {
			members.push(current);
			current = '';
			continue;
		}
		current += char;
	}
	if (current.trim()) members.push(current);
	return members;
}

function parseParameters(value: string): Record<string, string> {
	const params: Record<string, string> = {};
	const regex = /;\s*([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^;]+))/g;
	let match: RegExpExecArray | null;
	while ((match = regex.exec(value)) !== null) {
		params[match[1].toLowerCase()] = (match[2] ?? match[3] ?? '').trim();
	}
	return params;
}

/** Parses one or more `Signature-Input` members. */
export function parseSignatureInput(value: string): ParsedSignatureMember[] {
	const members: ParsedSignatureMember[] = [];
	for (const raw of splitMembers(value)) {
		const equals = raw.indexOf('=');
		if (equals < 1) continue;
		const label = raw.slice(0, equals).trim();
		const rest = raw.slice(equals + 1).trim();
		if (!rest.startsWith('(')) continue;
		const close = rest.indexOf(')');
		if (close < 0) continue;
		const components = [...rest.slice(1, close).matchAll(/"([^"]+)"/g)].map((match) => match[1]);
		if (components.length === 0) continue;
		members.push({ label, components, params: parseParameters(rest.slice(close + 1)), paramsString: rest });
	}
	return members;
}

/** Extracts `label=:base64:` from the `Signature` header. */
export function extractSignatureValue(header: string, label: string): string | null {
	for (const raw of splitMembers(header)) {
		const equals = raw.indexOf('=');
		if (equals < 1) continue;
		if (raw.slice(0, equals).trim() !== label) continue;
		const value = raw.slice(equals + 1).trim();
		const match = value.match(/^:([^:]*):$/);
		return match ? match[1] : null;
	}
	return null;
}

/** Checks an RFC 9530 `Content-Digest` header against the body. */
export async function contentDigestMatches(header: string, body: string): Promise<boolean> {
	const expected = await sha256Base64(body);
	for (const part of header.split(',')) {
		const index = part.indexOf('=');
		if (index < 0) continue;
		if (part.slice(0, index).trim().toLowerCase() !== 'sha-256') continue;
		const value = part.slice(index + 1).trim().replace(/^:|:$/g, '');
		return timingSafeEqual(value, expected);
	}
	return false;
}

export interface Rfc9421SigningInput {
	method: string;
	url: string;
	body?: string | null;
	privateKeyPem: string;
	keyId: string;
	contentType?: string;
}

/** Signs an outbound request with RFC 9421 and returns all required headers. */
export async function signRfc9421Request(input: Rfc9421SigningInput): Promise<Record<string, string>> {
	const method = input.method.toUpperCase();
	const url = new URL(input.url);
	url.hash = '';
	const values: Record<string, string> = { date: new Date().toUTCString(), host: url.host };
	const components = ['@method', '@authority', '@target-uri'];
	if (input.body != null) {
		values['content-digest'] = `sha-256=:${await sha256Base64(input.body)}:`;
		values['content-type'] = input.contentType ?? 'application/activity+json';
		components.push('content-digest', 'content-type');
	}
	components.push('date');
	const paramsString = `(${components.map((component) => `"${component}"`).join(' ')});keyid="${input.keyId}";alg="${RFC9421_ALGORITHM}";tag="${RFC9421_SIGNATURE_TAG}";nonce="${randomToken(32)}";created=${Math.floor(Date.now() / 1000)}`;
	const signingString = buildSigningString(components, {
		method,
		targetUri: url.toString(),
		authority: url.host,
		headers: values,
		paramsString,
	});
	const key = await importPrivateKey(input.privateKeyPem);
	const signature = new Uint8Array(await crypto.subtle.sign(RSA_ALGORITHM, key, utf8(signingString)));
	const headers: Record<string, string> = { Date: values.date, Host: values.host };
	if (values['content-digest']) headers['Content-Digest'] = values['content-digest'];
	if (values['content-type']) headers['Content-Type'] = values['content-type'];
	return {
		...headers,
		'Signature-Input': `${RFC9421_SIGNATURE_LABEL}=${paramsString}`,
		Signature: `${RFC9421_SIGNATURE_LABEL}=:${bytesToBase64(signature)}:`,
	};
}

interface SigningStringContext {
	method: string;
	targetUri: string;
	authority: string;
	headers: Record<string, string>;
	paramsString: string;
}

function componentValue(component: string, context: SigningStringContext): string | null {
	switch (component) {
		case '@method':
			return context.method.toUpperCase();
		case '@target-uri':
			return context.targetUri;
		case '@authority':
			return context.authority;
		case '@scheme':
			return new URL(context.targetUri).protocol.replace(/:$/, '');
		case '@path':
			return new URL(context.targetUri).pathname;
		case '@query':
			return `?${new URL(context.targetUri).search.replace(/^\?/, '')}`;
		case '@request-target': {
			const url = new URL(context.targetUri);
			return `${context.method.toLowerCase()} ${url.pathname}${url.search}`;
		}
		default: {
			const value = context.headers[component.toLowerCase()];
			return value ?? null;
		}
	}
}

function buildSigningString(components: string[], context: SigningStringContext): string {
	const lines: string[] = [];
	for (const component of components) {
		const value = componentValue(component, context);
		if (value === null) throw new Error(`missing component value: ${component}`);
		lines.push(`"${component}": ${value}`);
	}
	lines.push(`"@signature-params": ${context.paramsString}`);
	return lines.join('\n');
}

export interface Rfc9421VerificationInput {
	method: string;
	url: string;
	headers: Record<string, string>;
	body: string;
	publicKeyPem: string;
	expectedAuthority?: string;
	/** Restricts verification to a single `Signature-Input` member label. */
	label?: string;
}

export interface Rfc9421VerificationResult {
	ok: boolean;
	error?: string;
	keyId?: string;
	nonce?: string;
}

/** Verifies an inbound RFC 9421 `activitypub` signature. */
export async function verifyRfc9421Signature(input: Rfc9421VerificationInput): Promise<Rfc9421VerificationResult> {
	if (input.method.toUpperCase() !== 'POST') return { ok: false, error: 'RFC 9421 verification only supports POST' };
	const members = parseSignatureInput(input.headers['signature-input'] ?? '');
	if (members.length === 0) return { ok: false, error: 'no signature members found' };

	const url = new URL(input.url);
	url.hash = '';
	if (input.expectedAuthority && url.host !== input.expectedAuthority) {
		return { ok: false, error: 'request authority does not match the relay hostname' };
	}
	if (!(await contentDigestMatches(input.headers['content-digest'] ?? '', input.body))) {
		return { ok: false, error: 'Content-Digest does not match the request body' };
	}

	let key: CryptoKey;
	try {
		key = await importPublicKey(input.publicKeyPem);
	} catch {
		return { ok: false, error: 'unable to parse the actor public key' };
	}

	// Prefer the Fediverse `activitypub` tag, but accept untagged members:
	// Mastodon signs a minimal component set without a tag and falls back to
	// RFC 9421 after a failed draft-cavage attempt.
	const tagged = members.filter((member) => member.params.tag === RFC9421_SIGNATURE_TAG);
	const candidates = input.label ? members.filter((member) => member.label === input.label) : tagged.length > 0 ? tagged : members;
	if (candidates.length === 0) return { ok: false, error: `no signature member with label ${input.label}` };
	let lastError = 'signature verification failed';

	for (const member of candidates) {
		const verified = await verifySignatureMember(input, member, url, key);
		if (verified.ok) return verified;
		lastError = verified.error ?? lastError;
	}
	return { ok: false, error: lastError };
}

/** Verifies a single `Signature-Input` member against the request. */
async function verifySignatureMember(
	input: Rfc9421VerificationInput,
	member: ParsedSignatureMember,
	url: URL,
	key: CryptoKey,
): Promise<Rfc9421VerificationResult> {
	const { keyid, nonce, created, expires, alg } = member.params;
	if (!keyid) return { ok: false, error: 'signature is missing keyid' };
	if (alg && alg !== RFC9421_ALGORITHM) return { ok: false, error: `unsupported signature algorithm: ${alg}` };
	if (!created) return { ok: false, error: 'signature is missing created' };
	if (nonce && nonce.length > 256) return { ok: false, error: 'signature nonce is too long' };

	const createdSeconds = Number(created);
	const nowSeconds = Math.floor(Date.now() / 1000);
	if (!Number.isFinite(createdSeconds)) return { ok: false, error: 'signature created is not numeric' };
	if (createdSeconds > nowSeconds + MAX_CREATED_SKEW_SECONDS) return { ok: false, error: 'signature created is too far in the future' };
	if (createdSeconds < nowSeconds - MAX_CREATED_AGE_SECONDS) return { ok: false, error: 'signature created is too old' };
	if (expires) {
		const expiresSeconds = Number(expires);
		if (!Number.isFinite(expiresSeconds) || expiresSeconds < createdSeconds) return { ok: false, error: 'signature expires is invalid' };
		if (nowSeconds > expiresSeconds) return { ok: false, error: 'signature has expired' };
	}

	const seen = new Set<string>();
	for (const component of member.components) {
		if (seen.has(component)) return { ok: false, error: `duplicate signature component: ${component}` };
		seen.add(component);
	}
	for (const required of RFC9421_REQUIRED_POST_COMPONENTS) {
		if (!seen.has(required)) return { ok: false, error: `signature is missing required component: ${required}` };
	}

	let signingString: string;
	try {
		signingString = buildSigningString(member.components, {
			method: input.method,
			targetUri: url.toString(),
			authority: url.host,
			headers: input.headers,
			paramsString: member.paramsString,
		});
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : 'unable to build signing string' };
	}

	const signatureValue = extractSignatureValue(input.headers['signature'] ?? '', member.label);
	if (!signatureValue) return { ok: false, error: 'missing or malformed Signature header' };
	const valid = await crypto.subtle.verify(RSA_ALGORITHM, key, base64ToBytes(signatureValue), utf8(signingString));
	if (!valid) return { ok: false, error: 'signature verification failed' };
	return { ok: true, keyId: keyid, nonce };
}

function base64ToBytes(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
	let binary = '';
	for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
	return btoa(binary);
}
