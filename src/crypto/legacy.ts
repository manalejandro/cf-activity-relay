/**
 * Legacy Fediverse HTTP signatures (`Signature:` header, draft-cavage).
 *
 * The relay verifies inbound requests strictly (time window, digest binding,
 * signed-header strength) and signs outbound requests with
 * `(request-target) host date digest content-type`.
 */
import { importPrivateKey, importPublicKey, publicKeySpkiDer, RSA_ALGORITHM } from './keys';
import { sha256Base64, timingSafeEqual, utf8 } from './digest';

const MAX_SIGNATURE_AGE_MS = 12 * 3600 * 1000;
const CLOCK_SKEW_MS = 3600 * 1000;

export interface ParsedSignatureHeader {
	keyId?: string;
	algorithm?: string;
	headers?: string;
	signature?: string;
	created?: string;
	expires?: string;
}

/** Parses the comma separated `Signature` header parameters. */
export function parseSignatureHeader(value: string): ParsedSignatureHeader | null {
	if (!value.trim()) return null;
	const result: ParsedSignatureHeader = {};
	const regex = /([A-Za-z0-9_]+)\s*=\s*(?:"([^"]*)"|([^,;\s]+))/g;
	let match: RegExpExecArray | null;
	while ((match = regex.exec(value)) !== null) {
		const key = match[1].toLowerCase();
		const raw = match[2] ?? match[3] ?? '';
		if (key === 'keyid') result.keyId = raw;
		else if (key === 'algorithm') result.algorithm = raw;
		else if (key === 'headers') result.headers = raw;
		else if (key === 'signature') result.signature = raw;
		else if (key === 'created') result.created = raw;
		else if (key === 'expires') result.expires = raw;
	}
	return Object.keys(result).length > 0 ? result : null;
}

/** Builds the signing string from the covered header list. */
export function buildLegacySigningString(
	method: string,
	url: string,
	headers: Record<string, string>,
	headerList: string[],
	parsed: ParsedSignatureHeader,
	includeQuery: boolean,
): string {
	const urlObject = new URL(url);
	const target = includeQuery ? `${urlObject.pathname}${urlObject.search}` : urlObject.pathname;
	return headerList
		.map((header) => {
			if (header === '(request-target)') return `(request-target): ${method.toLowerCase()} ${target}`;
			if (header === '(created)') return `(created): ${parsed.created ?? ''}`;
			if (header === '(expires)') return `(expires): ${parsed.expires ?? ''}`;
			return `${header}: ${headers[header] ?? ''}`;
		})
		.join('\n');
}

export interface LegacyVerificationInput {
	method: string;
	url: string;
	headers: Record<string, string>;
	body: string;
	publicKeyPem: string;
}

export interface LegacyVerificationResult {
	ok: boolean;
	error?: string;
	keyId?: string;
}

/**
 * Verifies a draft-cavage signature. Mirrors Mastodon's signature-strength
 * rules so that only requests which bind the request target or the body digest
 * are accepted.
 */
export async function verifyLegacySignature(input: LegacyVerificationInput): Promise<LegacyVerificationResult> {
	const headers = input.headers;
	const parsed = parseSignatureHeader(headers['signature'] ?? '');
	if (!parsed) return { ok: false, error: 'missing or malformed Signature header' };
	if (!parsed.keyId || !parsed.signature) return { ok: false, error: 'Signature header is missing keyId or signature' };
	if (parsed.algorithm && !/^(rsa-sha256|hs2019)$/i.test(parsed.algorithm)) {
		return { ok: false, error: `unsupported signature algorithm: ${parsed.algorithm}` };
	}

	const method = input.method.toUpperCase();
	const headerList = (parsed.headers || 'date').toLowerCase().split(/\s+/).filter(Boolean);
	if (!headerList.includes('date') && !headerList.includes('(created)')) return { ok: false, error: 'signature does not cover date or (created)' };
	if (!headerList.includes('(request-target)') && !headerList.includes('digest')) return { ok: false, error: 'signature covers neither the request target nor the digest' };
	if (method === 'POST' && !headerList.includes('digest')) return { ok: false, error: 'POST signature does not cover the digest' };
	if (method === 'GET' && !headerList.includes('host')) return { ok: false, error: 'GET signature does not cover the host' };
	if (headerList.includes('(created)') && !parsed.created) return { ok: false, error: 'signature covers (created) but it is absent' };
	if (headerList.includes('(expires)') && !parsed.expires) return { ok: false, error: 'signature covers (expires) but it is absent' };

	if (parsed.created) {
		const createdMs = Number(parsed.created) * 1000;
		if (!Number.isFinite(createdMs) || Math.abs(Date.now() - createdMs) > MAX_SIGNATURE_AGE_MS + CLOCK_SKEW_MS) {
			return { ok: false, error: 'signature creation time is outside the accepted window' };
		}
	} else {
		const dateMs = Date.parse(headers['date'] ?? '');
		if (!Number.isFinite(dateMs) || Math.abs(Date.now() - dateMs) > MAX_SIGNATURE_AGE_MS + CLOCK_SKEW_MS) {
			return { ok: false, error: 'missing or stale Date header' };
		}
	}
	if (parsed.expires) {
		const expiresMs = Number(parsed.expires) * 1000;
		if (Number.isFinite(expiresMs) && Date.now() > expiresMs + CLOCK_SKEW_MS) return { ok: false, error: 'signature has expired' };
	}

	for (const header of headerList) {
		if (header.startsWith('(')) continue;
		if (headers[header] === undefined) return { ok: false, error: `signature covers missing header: ${header}` };
	}

	if (headerList.includes('digest')) {
		const matches = await digestHeaderMatches(headers['digest'] ?? '', input.body);
		if (!matches) return { ok: false, error: 'Digest header does not match the request body' };
	}

	let key: CryptoKey;
	try {
		key = await importPublicKey(input.publicKeyPem);
	} catch {
		return { ok: false, error: 'unable to parse the actor public key' };
	}

	const signatureBytes = base64ToBytes(parsed.signature);
	const urlObject = new URL(input.url);
	const candidates = [buildLegacySigningString(method, input.url, headers, headerList, parsed, true)];
	if (urlObject.search) candidates.push(buildLegacySigningString(method, input.url, headers, headerList, parsed, false));

	for (const candidate of candidates) {
		const valid = await crypto.subtle.verify(RSA_ALGORITHM, key, signatureBytes, utf8(candidate));
		if (valid) return { ok: true, keyId: parsed.keyId };
	}

	// `hs2019` may legitimately be RSA-PSS; retry with PSS/SHA-256 for interop.
	if (/^hs2019$/i.test(parsed.algorithm ?? '')) {
		try {
			const pssKey = await crypto.subtle.importKey('spki', publicKeySpkiDer(input.publicKeyPem), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
			for (const candidate of candidates) {
				const valid = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pssKey, signatureBytes, utf8(candidate));
				if (valid) return { ok: true, keyId: parsed.keyId };
			}
		} catch {
			// Fall through to the generic failure below.
		}
	}
	return { ok: false, error: 'signature verification failed' };
}

/** Checks the `Digest: SHA-256=base64` header against the body. */
export async function digestHeaderMatches(header: string, body: string): Promise<boolean> {
	const expected = await sha256Base64(body);
	for (const part of header.split(',')) {
		const index = part.indexOf('=');
		if (index < 0) continue;
		if (part.slice(0, index).trim().toLowerCase() !== 'sha-256') continue;
		return timingSafeEqual(part.slice(index + 1).trim(), expected);
	}
	return false;
}

export interface LegacySigningInput {
	method: string;
	url: string;
	body?: string | null;
	privateKeyPem: string;
	keyId: string;
	contentType?: string;
}

/**
 * Signs an outbound request with the legacy profile.
 * Returns the complete set of headers that must be transmitted.
 */
export async function signLegacyRequest(input: LegacySigningInput): Promise<Record<string, string>> {
	const method = input.method.toUpperCase();
	const urlObject = new URL(input.url);
	urlObject.hash = '';
	const target = `${urlObject.pathname}${urlObject.search}`;
	const values: Record<string, string> = {
		date: new Date().toUTCString(),
		host: urlObject.host,
	};
	const covered = ['(request-target)', 'host', 'date'];
	if (input.body != null) {
		values.digest = `SHA-256=${await sha256Base64(input.body)}`;
		values['content-type'] = input.contentType ?? 'application/activity+json';
		covered.push('digest', 'content-type');
	}
	const signingString = covered
		.map((header) => {
			if (header === '(request-target)') return `(request-target): ${method.toLowerCase()} ${target}`;
			return `${header}: ${values[header]}`;
		})
		.join('\n');
	const key = await importPrivateKey(input.privateKeyPem);
	const signature = new Uint8Array(await crypto.subtle.sign(RSA_ALGORITHM, key, utf8(signingString)));
	const signatureHeader = [
		`keyId="${input.keyId}"`,
		'algorithm="rsa-sha256"',
		`headers="${covered.join(' ')}"`,
		`signature="${bytesToBase64(signature)}"`,
	].join(',');
	const headers: Record<string, string> = { Date: values.date, Host: values.host };
	if (values.digest) headers.Digest = values.digest;
	if (values['content-type']) headers['Content-Type'] = values['content-type'];
	return { ...headers, Signature: signatureHeader };
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
