import type { RelayConfig } from '../config';
import type { Env } from '../env';
import { activityJsonResponse, methodNotAllowed } from '../utils/http';
import { buildRelayActor, emptyOrderedCollection } from '../ap/actor';

const READ_METHODS = ['GET', 'HEAD'];

/** `GET|HEAD /actor` — the public relay actor document. */
export async function handleActor(env: Env, config: RelayConfig, request: Request): Promise<Response> {
	if (!READ_METHODS.includes(request.method)) return methodNotAllowed('GET, HEAD');
	return activityJsonResponse(await buildRelayActor(env, config), request);
}

/** `GET|HEAD /actor/outbox`, `/actor/followers`, `/actor/following`. */
export function handleActorCollection(config: RelayConfig, request: Request, collection: 'outbox' | 'followers' | 'following'): Response {
	if (!READ_METHODS.includes(request.method)) return methodNotAllowed('GET, HEAD');
	return activityJsonResponse(emptyOrderedCollection(`${config.baseUrl}/actor/${collection}`), request);
}
