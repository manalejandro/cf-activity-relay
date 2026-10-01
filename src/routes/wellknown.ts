import type { RelayConfig } from '../config';
import type { Env } from '../env';
import { jsonResponse, methodNotAllowed } from '../utils/http';
import { nodeInfoDiscovery, nodeInfoDocument, webfingerDocument } from '../ap/actor';
import { listSubscribers } from '../store/repo';

/** `GET /.well-known/nodeinfo` */
export function handleNodeInfoDiscovery(config: RelayConfig, request: Request): Response {
	if (request.method !== 'GET') return new Response(null, { status: 400 });
	return jsonResponse(nodeInfoDiscovery(config));
}

/** `GET /.well-known/webfinger?resource=acct:relay@host` */
export function handleWebFinger(config: RelayConfig, request: Request, url: URL): Response {
	if (request.method !== 'GET') return new Response(null, { status: 400 });
	const resource = url.searchParams.get('resource');
	if (!resource) return new Response(null, { status: 400 });
	const accepted = resource === `acct:relay@${config.domain}` || resource === config.actorId;
	if (!accepted) return new Response(null, { status: 404 });
	return jsonResponse(webfingerDocument(config));
}

/** `GET /nodeinfo/2.1` */
export async function handleNodeInfo(env: Env, config: RelayConfig, request: Request): Promise<Response> {
	if (request.method !== 'GET') return new Response(null, { status: 400 });
	const subscribers = await listSubscribers(env.DB);
	return jsonResponse(nodeInfoDocument(config, subscribers.length));
}

export { methodNotAllowed };
