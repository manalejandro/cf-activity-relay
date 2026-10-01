import { ACTIVITY_JSON_CONTENT_TYPE, JSON_CONTENT_TYPE } from '../config';

const JSON_HEADERS = {
	'Content-Type': JSON_CONTENT_TYPE,
	'X-Content-Type-Options': 'nosniff',
} as const;

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set('Content-Type', JSON_CONTENT_TYPE);
	headers.set('X-Content-Type-Options', 'nosniff');
	return new Response(JSON.stringify(body), { ...init, headers });
}

export function textResponse(body: string, status: number, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set('X-Content-Type-Options', 'nosniff');
	return new Response(body, { ...init, status, headers });
}

/**
 * Responds with ActivityStreams JSON. `HEAD` requests receive identical
 * headers without a body.
 */
export function activityJsonResponse(body: unknown, request: Request, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set('Content-Type', ACTIVITY_JSON_CONTENT_TYPE);
	headers.set('X-Content-Type-Options', 'nosniff');
	if (request.method === 'HEAD') {
		return new Response(null, { ...init, headers });
	}
	return new Response(JSON.stringify(body), { ...init, headers });
}

export function methodNotAllowed(allow: string): Response {
	return new Response(null, { status: 405, headers: { Allow: allow, 'X-Content-Type-Options': 'nosniff' } });
}

export function notFound(): Response {
	return textResponse('not found', 404);
}

/**
 * Reads a request body while enforcing a hard byte limit. Returns `null` when
 * the body exceeds the limit so callers can answer with a bounded error.
 */
export async function readBodyBounded(request: Request, maxBytes: number): Promise<string | null> {
	const reader = request.body?.getReader();
	if (!reader) return '';
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel().catch(() => undefined);
			return null;
		}
		chunks.push(value);
	}
	const merged = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		merged.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(merged);
}

/** Reads a bounded amount of a remote response body for diagnostics. */
export async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
	try {
		const text = await response.text();
		const collapsed = text.replace(/\s+/g, ' ').trim();
		return collapsed.length > maxBytes ? `${collapsed.slice(0, maxBytes)}[truncated]` : collapsed;
	} catch {
		return '';
	}
}

/** Reads a response body while enforcing a hard byte limit. */
export async function readTextBounded(response: Response, maxBytes: number): Promise<string | null> {
	const reader = response.body?.getReader();
	if (!reader) return '';
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel().catch(() => undefined);
			return null;
		}
		chunks.push(value);
	}
	const merged = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		merged.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(merged);
}

/** Cancels an unread response body to release the connection. */
export async function discardBody(response: Response | null | undefined): Promise<void> {
	try {
		await response?.body?.cancel();
	} catch {
		// Ignore: the body may already be consumed.
	}
}

export { JSON_HEADERS };
