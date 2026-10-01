import { beforeAll, describe, expect, it } from 'vitest';
import { generateRsaKeyPair, importPrivateKey, importPublicKey, parsePem, pkcs1ToPkcs8, pkcs1ToSpki, publicKeyPemFromPrivate, publicKeySpkiDer, RSA_ALGORITHM } from '../src/crypto/keys';
import { digestHeaderMatches, parseSignatureHeader, signLegacyRequest, verifyLegacySignature } from '../src/crypto/legacy';
import { contentDigestMatches, parseSignatureInput, signRfc9421Request, verifyRfc9421Signature } from '../src/crypto/rfc9421';
import { sha256Base64, timingSafeEqual } from '../src/crypto/digest';

const KEY_ID = 'https://remote.example/actor#main-key';
const URL = 'https://relay.example/inbox';

let privateKeyPem = '';
let publicKeyPem = '';

function lowerHeaders(headers: Record<string, string>): Record<string, string> {
	return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
}

beforeAll(async () => {
	const pair = await generateRsaKeyPair(2048);
	privateKeyPem = pair.privateKeyPem;
	publicKeyPem = pair.publicKeyPem;
});

describe('RSA key handling', () => {
	it('generates importable PEM keys', async () => {
		expect(privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
		expect(publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
		await expect(importPrivateKey(privateKeyPem)).resolves.toBeTruthy();
		await expect(importPublicKey(publicKeyPem)).resolves.toBeTruthy();
	});

	it('derives the public key from the private key', async () => {
		expect(await publicKeyPemFromPrivate(privateKeyPem)).toBe(publicKeyPem);
	});

	it('wraps PKCS#1 structures into their modern containers', () => {
		const pkcs1 = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);
		expect(pkcs1ToSpki(pkcs1)[0]).toBe(0x30);
		expect(pkcs1ToPkcs8(pkcs1)[0]).toBe(0x30);
		expect(parsePem(publicKeyPem).label).toBe('PUBLIC KEY');
		expect(publicKeySpkiDer(publicKeyPem).length).toBeGreaterThan(0);
	});
});

describe('legacy HTTP signatures', () => {
	it('signs and verifies a POST round trip', async () => {
		const body = JSON.stringify({ type: 'Create', actor: 'https://remote.example/actor' });
		const signed = await signLegacyRequest({ method: 'POST', url: URL, body, privateKeyPem, keyId: KEY_ID });
		expect(signed.Signature).toContain('algorithm="rsa-sha256"');
		expect(signed.Digest).toMatch(/^SHA-256=/);
		const result = await verifyLegacySignature({ method: 'POST', url: URL, headers: lowerHeaders(signed), body, publicKeyPem });
		expect(result.ok).toBe(true);
		expect(result.keyId).toBe(KEY_ID);
	});

	it('rejects a tampered body', async () => {
		const body = JSON.stringify({ type: 'Create' });
		const signed = await signLegacyRequest({ method: 'POST', url: URL, body, privateKeyPem, keyId: KEY_ID });
		const result = await verifyLegacySignature({ method: 'POST', url: URL, headers: lowerHeaders(signed), body: `${body} `, publicKeyPem });
		expect(result.ok).toBe(false);
	});

	it('rejects a signature without a digest', async () => {
		const body = JSON.stringify({ type: 'Create' });
		const signed = await signLegacyRequest({ method: 'POST', url: URL, body, privateKeyPem, keyId: KEY_ID });
		const headers = lowerHeaders(signed);
		delete headers.digest;
		const result = await verifyLegacySignature({ method: 'POST', url: URL, headers, body, publicKeyPem });
		expect(result.ok).toBe(false);
	});

	it('parses signature header parameters', () => {
		const parsed = parseSignatureHeader('keyId="https://a.example/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date",signature="abc"');
		expect(parsed?.keyId).toBe('https://a.example/actor#main-key');
		expect(parsed?.algorithm).toBe('rsa-sha256');
		expect(parsed?.signature).toBe('abc');
	});

	it('matches digest headers', async () => {
		const body = 'hello world';
		expect(await digestHeaderMatches(`SHA-256=${await sha256Base64(body)}`, body)).toBe(true);
		expect(await digestHeaderMatches('SHA-256=wrong', body)).toBe(false);
	});
});

describe('RFC 9421 HTTP message signatures', () => {
	it('signs and verifies a POST round trip', async () => {
		const body = JSON.stringify({ type: 'Create', actor: 'https://remote.example/actor' });
		const signed = await signRfc9421Request({ method: 'POST', url: URL, body, privateKeyPem, keyId: KEY_ID });
		expect(signed['Signature-Input']).toContain('tag="activitypub"');
		expect(signed['Content-Digest']).toMatch(/^sha-256=:/);
		const headers = lowerHeaders(signed);
		const result = await verifyRfc9421Signature({
			method: 'POST',
			url: URL,
			headers,
			body,
			publicKeyPem,
			expectedAuthority: 'relay.example',
		});
		expect(result.ok, result.error).toBe(true);
		expect(result.keyId).toBe(KEY_ID);
		expect(result.nonce).toBeTruthy();
	});

	it('rejects a tampered body', async () => {
		const body = JSON.stringify({ type: 'Create' });
		const signed = await signRfc9421Request({ method: 'POST', url: URL, body, privateKeyPem, keyId: KEY_ID });
		const result = await verifyRfc9421Signature({ method: 'POST', url: URL, headers: lowerHeaders(signed), body: '{"type":"Delete"}', publicKeyPem });
		expect(result.ok).toBe(false);
	});

	it('rejects a wrong authority', async () => {
		const body = JSON.stringify({ type: 'Create' });
		const signed = await signRfc9421Request({ method: 'POST', url: URL, body, privateKeyPem, keyId: KEY_ID });
		const result = await verifyRfc9421Signature({
			method: 'POST',
			url: URL,
			headers: lowerHeaders(signed),
			body,
			publicKeyPem,
			expectedAuthority: 'other.example',
		});
		expect(result.ok).toBe(false);
	});

	it('verifies a Mastodon-style minimal component signature', async () => {
		// Mastodon retries with RFC 9421 after a failed draft-cavage attempt and
		// signs only @method, @target-uri and content-digest, without a tag.
		const body = JSON.stringify({ type: 'Delete', actor: 'https://mastodon.social/users/example' });
		const contentDigest = `sha-256=:${await sha256Base64(body)}:`;
		const params = `("@method" "@target-uri" "content-digest");created=${Math.floor(Date.now() / 1000)};keyid="${KEY_ID}";alg="rsa-v1_5-sha256"`;
		const signingString = [`"@method": POST`, `"@target-uri": ${URL}`, `"content-digest": ${contentDigest}`, `"@signature-params": ${params}`].join('\n');
		const key = await importPrivateKey(privateKeyPem);
		const signature = new Uint8Array(await crypto.subtle.sign(RSA_ALGORITHM, key, new TextEncoder().encode(signingString)));
		const result = await verifyRfc9421Signature({
			method: 'POST',
			url: URL,
			headers: {
				'content-digest': contentDigest,
				'signature-input': `sig1=${params}`,
				signature: `sig1=:${btoa(String.fromCharCode(...signature))}:`,
			},
			body,
			publicKeyPem,
			expectedAuthority: 'relay.example',
		});
		expect(result.ok, result.error).toBe(true);
		expect(result.keyId).toBe(KEY_ID);
	});

	it('requires the request target to be covered', async () => {
		const body = JSON.stringify({ type: 'Create' });
		const contentDigest = `sha-256=:${await sha256Base64(body)}:`;
		const params = `("@method" "content-digest");created=${Math.floor(Date.now() / 1000)};keyid="${KEY_ID}"`;
		const signingString = [`"@method": POST`, `"content-digest": ${contentDigest}`, `"@signature-params": ${params}`].join('\n');
		const key = await importPrivateKey(privateKeyPem);
		const signature = new Uint8Array(await crypto.subtle.sign(RSA_ALGORITHM, key, new TextEncoder().encode(signingString)));
		const result = await verifyRfc9421Signature({
			method: 'POST',
			url: URL,
			headers: {
				'content-digest': contentDigest,
				'signature-input': `sig1=${params}`,
				signature: `sig1=:${btoa(String.fromCharCode(...signature))}:`,
			},
			body,
			publicKeyPem,
		});
		expect(result.ok).toBe(false);
	});

	it('parses signature-input members verbatim', () => {
		const members = parseSignatureInput('sig1=("@method" "@target-uri");keyid="k";alg="rsa-v1_5-sha256";tag="activitypub";created=1234');
		expect(members).toHaveLength(1);
		expect(members[0].components).toEqual(['@method', '@target-uri']);
		expect(members[0].params.keyid).toBe('k');
		expect(members[0].paramsString).toContain('("@method" "@target-uri")');
	});

	it('matches RFC 9530 content digests', async () => {
		const body = 'hello world';
		expect(await contentDigestMatches(`sha-256=:${await sha256Base64(body)}:`, body)).toBe(true);
		expect(await contentDigestMatches('sha-256=:AAAA:', body)).toBe(false);
	});
});

describe('digest utilities', () => {
	it('compares in constant time', () => {
		expect(timingSafeEqual('abc', 'abc')).toBe(true);
		expect(timingSafeEqual('abc', 'abd')).toBe(false);
		expect(timingSafeEqual('abc', 'ab')).toBe(false);
	});
});
