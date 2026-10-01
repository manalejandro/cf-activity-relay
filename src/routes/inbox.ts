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
				console.warn('rejected inbox activity: body exceeds MAX_ACTIVITY_BYTES', { limit: config.maxActivityBytes });
				return textResponse('', 400);
			}
			const identity = await getRelayIdentity(env, config);
			const result = await processInboundActivity(env, config, identity, request, body);
			if (result.status >= 400) {
				console.warn('rejected inbox activity', {
					status: result.status,
					userAgent: request.headers.get('user-agent')?.slice(0, 256) ?? '',
					reason: result.text?.slice(0, 512) ?? 'verification failed',
				});
			}
			return textResponse(result.text ?? '', result.status);
		}
		default:
			return methodNotAllowed('GET, HEAD, POST');
	}
}
