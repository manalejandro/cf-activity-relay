/**
 * PEM/DER helpers and RSA key handling built on Web Crypto.
 *
 * The relay stores its own key as PKCS#8 (`PRIVATE KEY`) and SPKI
 * (`PUBLIC KEY`). For interoperability it also accepts the historical PKCS#1
 * encodings (`RSA PRIVATE KEY` / `RSA PUBLIC KEY`) used by some remote actors.
 */

export const RSA_ALGORITHM = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const;

interface PemBlock {
	label: string;
	der: Uint8Array;
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

function derLength(length: number): Uint8Array {
	if (length < 0x80) return new Uint8Array([length]);
	const bytes: number[] = [];
	let value = length;
	while (value > 0) {
		bytes.unshift(value & 0xff);
		value >>>= 8;
	}
	return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function derTag(tag: number, content: Uint8Array): Uint8Array {
	const length = derLength(content.length);
	const out = new Uint8Array(1 + length.length + content.length);
	out[0] = tag;
	out.set(length, 1);
	out.set(content, 1 + length.length);
	return out;
}

function derSequence(...parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const part of parts) total += part.length;
	const content = new Uint8Array(total);
	let offset = 0;
	for (const part of parts) {
		content.set(part, offset);
		offset += part.length;
	}
	return derTag(0x30, content);
}

function derInteger(value: number): Uint8Array {
	return derTag(0x02, new Uint8Array([value]));
}

function derOctetString(content: Uint8Array): Uint8Array {
	return derTag(0x04, content);
}

function derBitString(content: Uint8Array): Uint8Array {
	const body = new Uint8Array(content.length + 1);
	body[0] = 0x00;
	body.set(content, 1);
	return derTag(0x03, body);
}

// rsaEncryption: 1.2.840.113549.1.1.1
const RSA_OID = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const NULL_VALUE = new Uint8Array([0x05, 0x00]);

function rsaAlgorithmIdentifier(): Uint8Array {
	return derSequence(RSA_OID, NULL_VALUE);
}

/** Wraps a PKCS#1 RSAPublicKey structure into an X.509 SPKI structure. */
export function pkcs1ToSpki(pkcs1: Uint8Array): Uint8Array {
	return derSequence(rsaAlgorithmIdentifier(), derBitString(pkcs1));
}

/** Wraps a PKCS#1 RSAPrivateKey structure into a PKCS#8 structure. */
export function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
	return derSequence(derInteger(0), rsaAlgorithmIdentifier(), derOctetString(pkcs1));
}

export function parsePem(pem: string): PemBlock {
	const match = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/);
	if (!match) throw new Error('invalid PEM document');
	return { label: match[1].trim(), der: base64ToBytes(match[2].replace(/\s+/g, '')) };
}

export function derToPem(der: Uint8Array, label: string): string {
	const base64 = bytesToBase64(der);
	const lines = base64.match(/.{1,64}/g)?.join('\n') ?? base64;
	return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

export interface GeneratedKeyPair {
	publicKeyPem: string;
	privateKeyPem: string;
}

/** Generates a fresh RSA key pair in PEM form. */
export async function generateRsaKeyPair(modulusLength = 2048): Promise<GeneratedKeyPair> {
	const pair = (await crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
		true,
		['sign', 'verify'],
	)) as CryptoKeyPair;
	const [spki, pkcs8] = (await Promise.all([crypto.subtle.exportKey('spki', pair.publicKey), crypto.subtle.exportKey('pkcs8', pair.privateKey)])) as [
		ArrayBuffer,
		ArrayBuffer,
	];
	return {
		publicKeyPem: derToPem(new Uint8Array(spki), 'PUBLIC KEY'),
		privateKeyPem: derToPem(new Uint8Array(pkcs8), 'PRIVATE KEY'),
	};
}

/** Imports an RSA private key from PKCS#8 or PKCS#1 PEM for signing. */
export async function importPrivateKey(pem: string): Promise<CryptoKey> {
	const block = parsePem(pem);
	if (block.label === 'RSA PRIVATE KEY') {
		return crypto.subtle.importKey('pkcs8', pkcs1ToPkcs8(block.der), RSA_ALGORITHM, false, ['sign']);
	}
	if (block.label === 'PRIVATE KEY') {
		return crypto.subtle.importKey('pkcs8', block.der, RSA_ALGORITHM, false, ['sign']);
	}
	throw new Error(`unsupported private key label: ${block.label}`);
}

/** Imports an RSA public key from SPKI or PKCS#1 PEM for verification. */
export async function importPublicKey(pem: string): Promise<CryptoKey> {
	const block = parsePem(pem);
	if (block.label === 'RSA PUBLIC KEY') {
		return crypto.subtle.importKey('spki', pkcs1ToSpki(block.der), RSA_ALGORITHM, false, ['verify']);
	}
	if (block.label === 'PUBLIC KEY') {
		return crypto.subtle.importKey('spki', block.der, RSA_ALGORITHM, false, ['verify']);
	}
	throw new Error(`unsupported public key label: ${block.label}`);
}

/** Returns the SPKI DER bytes of an SPKI or PKCS#1 public key PEM. */
export function publicKeySpkiDer(pem: string): Uint8Array {
	const block = parsePem(pem);
	return block.label === 'RSA PUBLIC KEY' ? pkcs1ToSpki(block.der) : block.der;
}

/** Derives the SPKI PEM public key of a PKCS#8/PKCS#1 private key. */
export async function publicKeyPemFromPrivate(privateKeyPem: string): Promise<string> {
	const block = parsePem(privateKeyPem);
	const pkcs8 = block.label === 'RSA PRIVATE KEY' ? pkcs1ToPkcs8(block.der) : block.der;
	const key = await crypto.subtle.importKey('pkcs8', pkcs8, RSA_ALGORITHM, true, ['sign']);
	// RSA JWKs always expose the public modulus and exponent, so the public key
	// can be reconstructed without re-deriving it from the PKCS#1 structure.
	const jwk = (await crypto.subtle.exportKey('jwk', key)) as JsonWebKey;
	const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, RSA_ALGORITHM, true, ['verify']);
	const spki = (await crypto.subtle.exportKey('spki', publicKey)) as ArrayBuffer;
	return derToPem(new Uint8Array(spki), 'PUBLIC KEY');
}

/** Returns true when the value looks like a usable RSA private key PEM. */
export function isPrivateKeyPem(value: string | undefined | null): boolean {
	return Boolean(value && /-----BEGIN (RSA )?PRIVATE KEY-----/.test(value));
}
