/** SHA-256 helpers shared by both signature profiles. */

const encoder = new TextEncoder();

export function utf8(value: string): Uint8Array {
	return encoder.encode(value);
}

export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
	const bytes = typeof data === 'string' ? encoder.encode(data) : data;
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return new Uint8Array(digest);
}

export async function sha256Base64(data: string | Uint8Array): Promise<string> {
	const digest = await sha256(data);
	let binary = '';
	for (let i = 0; i < digest.length; i += 1) binary += String.fromCharCode(digest[i]);
	return btoa(binary);
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
	const digest = await sha256(data);
	return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Constant-time comparison for short digests and signatures. */
export function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let mismatch = 0;
	for (let i = 0; i < a.length; i += 1) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return mismatch === 0;
}

/** Random URL-safe token used as an RFC 9421 nonce. */
export function randomToken(bytes = 32): string {
	const buffer = new Uint8Array(bytes);
	crypto.getRandomValues(buffer);
	let binary = '';
	for (let i = 0; i < buffer.length; i += 1) binary += String.fromCharCode(buffer[i]);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
