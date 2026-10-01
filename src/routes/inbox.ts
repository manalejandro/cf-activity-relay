import type { RelayConfig } from '../config';
import type { Env } from '../env';
import { getRelayIdentity } from '../ap/identity';
import { processInboundActivity } from '../ap/inbound';
import { emptyOrderedCollection } from '../ap/actor';
import { activityJsonResponse, methodNotAllowed, readBodyBounded, textResponse } from '../utils/http';

/**
 * `/inbox` — the shared inbox for traditional subscriptions and relayed
 * traffic. `GET` returns an empty collection, `POST` accepts signed activities.
 */
export async function handleInbox(env: Env, config: RelayConfig, request: Request): Promise<Response> {
	switch (request.method) {
		case 'GET':
		case 'HEAD':
			return activityJsonResponse(emptyOrderedCollection(`${config.baseUrl}/inbox`), request, { headers: { Allow: 'GET, HEAD, POST' } });
		case 'POST': {
			const body = await readBodyBounded(request, config.maxActivityBytes);
			if (body === null) {
				console.warn('inbox rejected', { status: 400, reason: 'body-too-large' });
				return textResponse('', 400);
			}
			const identity = await getRelayIdentity(env, config);
			const result = await processInboundActivity(env, config, identity, request, body);
			if (result.status >= 400) {
				console.warn('inbox rejected', { status: result.status, reason: result.reason ?? 'processing', keyHost: result.keyHost });
			}
			return textResponse(result.text ?? '', result.status);
		}
		default:
			return methodNotAllowed('GET, HEAD, POST');
	}
}
