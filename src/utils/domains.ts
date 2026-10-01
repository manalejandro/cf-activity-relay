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
	/^\[?::1\]?$/,
	/^\[?f[cd][0-9a-f]{2}:/i,
	/^\[?fe80:/i,
];

/** Blocks obvious SSRF targets before the relay performs a remote fetch. */
export function isPrivateHost(hostname: string): boolean {
	const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
	if (PRIVATE_HOST_PATTERNS.some((pattern) => pattern.test(host))) return true;
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
		const [a, b] = host.split('.').map(Number);
		if (a === 10 || a === 127 || a === 0) return true;
		if (a === 172 && b >= 16 && b <= 31) return true;
		if (a === 192 && b === 168) return true;
		if (a === 169 && b === 254) return true;
	}
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
