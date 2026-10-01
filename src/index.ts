/**
 * cf-activity-relay — an ActivityPub relay for Cloudflare Workers.
 *
 * The Worker exposes the relay actor, shared inbox, WebFinger and NodeInfo
 * endpoints, processes inbound activities synchronously, and fans deliveries
 * out through Cloudflare Queues.
 */
import { loadConfig, type RelayConfig } from './config';
import type { DeliveryMessage, Env } from './env';
import { consumeDeliveryBatch } from './ap/delivery';
import { cleanupExpired, ensureSchema } from './store/repo';
import { handleActor, handleActorCollection } from './routes/actor';
import { handleAdmin } from './routes/admin';
import { handleInbox } from './routes/inbox';
import { handleStatus } from './routes/status';
import { handleNodeInfo, handleNodeInfoDiscovery, handleWebFinger } from './routes/wellknown';

async function route(request: Request, env: Env, config: RelayConfig, url: URL): Promise<Response> {
	switch (url.pathname) {
		case '/actor':
			return handleActor(env, config, request);
		case '/actor/outbox':
			return handleActorCollection(config, request, 'outbox');
		case '/actor/followers':
			return handleActorCollection(config, request, 'followers');
		case '/actor/following':
			return handleActorCollection(config, request, 'following');
		case '/inbox':
			return handleInbox(env, config, request);
		case '/status.json':
			return handleStatus(env, config, request);
		case '/.well-known/nodeinfo':
			return handleNodeInfoDiscovery(config, request);
		case '/.well-known/webfinger':
			return handleWebFinger(config, request, url);
		case '/nodeinfo/2.1':
			return handleNodeInfo(env, config, request);
		case '/health':
			return new Response('ok', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
		default:
			break;
	}
	if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
		return handleAdmin(env, config, request, url);
	}
	if (request.method === 'GET' || request.method === 'HEAD') {
		const asset = await env.ASSETS.fetch(request);
		if (asset.status !== 404) return asset;
	}
	return new Response('not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		try {
			await ensureSchema(env.DB);
			const config = loadConfig(env);
			return await route(request, env, config, url);
		} catch (error) {
			console.error('unhandled request error', {
				path: url.pathname,
				error: error instanceof Error ? error.message : String(error),
			});
			return new Response('internal server error', { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
		}
	},

	async queue(batch: MessageBatch<DeliveryMessage>, env: Env): Promise<void> {
		await ensureSchema(env.DB);
		await consumeDeliveryBatch(batch, env);
	},

	async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
		await ensureSchema(env.DB);
		await cleanupExpired(env.DB);
		console.log('scheduled cleanup completed', { cron: controller.cron });
	},
} satisfies ExportedHandler<Env, DeliveryMessage>;
