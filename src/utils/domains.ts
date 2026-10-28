/** Domain and URL helpers shared across the relay. */

/** Lowercases a hostname and removes a trailing root dot. */
export function normalizeDomain(value: string | null | undefined): string {
	if (!value) return '';
	return value.trim().toLowerCase().replace(/\.$/, '');
}

/** Extracts and normalizes the hostname of an absolute URL. */
export function hostOf(value: string | null | undefined): string {
	if (!value) return '';
	try {
		return normalizeDomain(new URL(value).hostname);
	} catch {
		return '';
	}
}

/** Returns the full authority (host including a non-default port) of a URL. */
export function authorityOf(value: string): string {
	try {
		return new URL(value).host;
	} catch {
		return '';
	}
}

/** Parses an absolute HTTP(S) URL, rejecting credentials and other schemes. */
export function parseHttpUrl(value: string): URL | null {
	try {
		const url = new URL(value);
		if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
		if (url.username || url.password) return null;
		if (!url.hostname) return null;
		return url;
	} catch {
		return null;
	}
}

/** Removes the fragment portion of a URL, keeping it otherwise verbatim. */
export function stripFragment(value: string): string {
	const index = value.indexOf('#');
	return index === -1 ? value : value.slice(0, index);
}

const PRIVATE_HOST_PATTERNS = [
	/^localhost$/i,
	/\.localhost$/i,
	/\.local$/i,
	/\.internal$/i,
];

/**
 * Expands dotted-quad and abbreviated IPv4 literals (`127.1`, `10.2`,
 * `2130706433`) with inet_aton semantics into four octets. Returns null when
 * the value is not a syntactically valid IPv4 literal.
 */
export function expandIpv4(host: string): [number, number, number, number] | null {
	const parts = host.split('.');
	if (parts.length === 0 || parts.length > 4) return null;
	const nums: number[] = [];
	for (const part of parts) {
		if (!/^\d+$/.test(part)) return null;
		// Leading zeros denote octal notation in inet_aton: refuse to guess.
		if (part.length > 1 && part.startsWith('0')) return null;
		nums.push(Number(part));
	}
	const lastMax = [0xffffffff, 0xffffff, 0xffff, 0xff][nums.length - 1];
	if (nums[nums.length - 1] > lastMax) return null;
	if (nums.slice(0, -1).some((value) => value > 255)) return null;
	const tail = nums[nums.length - 1];
	const octets: [number, number, number, number] = [0, 0, 0, 0];
	octets[3] = tail & 0xff;
	octets[2] = (tail >> 8) & 0xff;
	octets[1] = (tail >> 16) & 0xff;
	if (nums.length === 1) octets[0] = (tail >> 24) & 0xff;
	nums.slice(0, -1).forEach((value, index) => {
		octets[index] = value;
	});
	return octets;
}

function isPrivateIpv4(octets: [number, number, number, number]): boolean {
	const [a, b] = octets;
	if (a === 0 || a === 10 || a === 127) return true;
	if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
	if (a === 169 && b === 254) return true; // link-local
	if (a === 172 && b >= 16 && b <= 31) return true;
	if (a === 192 && (b === 0 || b === 168)) return true; // incl. 192.0.2.0/24
	if (a === 198 && b >= 18 && b <= 19) return true; // benchmarking
	if (a === 198 && b === 51) return true; // 198.51.100.0/24
	if (a === 203 && b === 0) return true; // 203.0.113.0/24
	if (a >= 224) return true; // multicast + reserved + broadcast
	return false;
}

function isPrivateIpv6(host: string): boolean {
	const bare = host.split('%')[0];
	const mapped = bare.match(/^(?:.*:)?ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	if (mapped) {
		const octets = expandIpv4(mapped[1]);
		return !octets || isPrivateIpv4(octets);
	}
	if (bare === '::' || bare === '::1') return true;
	if (bare.startsWith('::')) return true; // unspecified-form addresses
	const first = bare.split(':')[0];
	const head = Number.parseInt(first, 16);
	if (!Number.isFinite(head)) return true;
	if ((head & 0xfe00) === 0xfc00) return true; // unique-local fc00::/7
	if ((head & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
	return false;
}

/** Blocks obvious SSRF targets before the relay performs a remote fetch. */
export function isPrivateHost(hostname: string): boolean {
	const raw = hostname.trim().toLowerCase();
	if (!raw) return true;
	const host = raw.replace(/^\[|\]$/g, '');
	if (PRIVATE_HOST_PATTERNS.some((pattern) => pattern.test(host))) return true;
	if (/^[\d.]+$/.test(host)) {
		const octets = expandIpv4(host);
		// A malformed numeric literal is never a legitimate federation host.
		if (!octets) return true;
		return isPrivateIpv4(octets);
	}
	if (host.includes(':')) return isPrivateIpv6(host);
	// Hexadecimal or octal IPv4 spellings (`0x7f000001`, `0177.0.0.1`).
	if (/^(0x[0-9a-f]+|0\d+)(\.(0x[0-9a-f]+|0?\d+)){0,3}$/i.test(host)) return true;
	return false;
}

/** True when the value is a syntactically valid, publicly routable HTTP(S) URL. */
export function isDeliverableUrl(value: string): boolean {
	const url = parseHttpUrl(value);
	if (!url) return false;
	return !isPrivateHost(url.hostname);
}

/** Canonicalizes an origin for capability-evidence keying. */
export function normalizeOrigin(value: string): string | null {
	const url = parseHttpUrl(value);
	if (!url) return null;
	const port = url.port && url.port !== '80' && url.port !== '443' ? `:${url.port}` : '';
	return `${url.protocol}//${normalizeDomain(url.hostname)}${port}`;
}

/** Normalizes a value that may be a single string or an array of strings. */
export function asStringArray(value: unknown): string[] {
	if (typeof value === 'string') return [value];
	if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === 'string');
	return [];
}

/** Extracts the `id` of an activity object, whether it is a string or a map. */
export function objectId(object: unknown): string | null {
	if (typeof object === 'string') return object;
	if (object && typeof object === 'object' && !Array.isArray(object)) {
		const id = (object as Record<string, unknown>).id;
		if (typeof id === 'string') return id;
	}
	return null;
}

/** True when the object is an embedded ActivityStreams document. */
export function isEmbeddedObject(object: unknown): object is Record<string, unknown> {
	return Boolean(object) && typeof object === 'object' && !Array.isArray(object);
}
