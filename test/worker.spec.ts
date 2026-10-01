import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

const RELAY = 'https://relay.manalejandro.com';

describe('relay HTTP surface', () => {
	it('serves the actor document', async () => {
		const response = await SELF.fetch(`${RELAY}/actor`);
		expect(response.status).toBe(200);
		expect(response.headers.get('content-type')).toBe('application/activity+json');
		const actor = (await response.json()) as Record<string, any>;
		expect(actor.id).toBe(`${RELAY}/actor`);
		expect(actor.type).toBe('Application');
		expect(actor.preferredUsername).toBe('relay');
		expect(actor.inbox).toBe(`${RELAY}/inbox`);
		expect(actor.endpoints.sharedInbox).toBe(`${RELAY}/inbox`);
		expect(actor.publicKey.id).toBe(`${RELAY}/actor#main-key`);
		expect(actor.publicKey.owner).toBe(`${RELAY}/actor`);
		expect(actor.publicKey.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
	});

	it('answers HEAD without a body', async () => {
		const response = await SELF.fetch(`${RELAY}/actor`, { method: 'HEAD' });
		expect(response.status).toBe(200);
		expect(await response.text()).toBe('');
	});

	it('rejects unsupported methods on the actor', async () => {
		const response = await SELF.fetch(`${RELAY}/actor`, { method: 'POST' });
		expect(response.status).toBe(405);
		expect(response.headers.get('allow')).toBe('GET, HEAD');
	});

	it('serves empty actor collections', async () => {
		for (const collection of ['outbox', 'followers', 'following']) {
			const response = await SELF.fetch(`${RELAY}/actor/${collection}`);
			expect(response.status).toBe(200);
			const document = (await response.json()) as Record<string, unknown>;
			expect(document.type).toBe('OrderedCollection');
			expect(document.totalItems).toBe(0);
			expect(document.orderedItems).toEqual([]);
		}
	});

	it('serves the shared inbox collection on GET', async () => {
		const response = await SELF.fetch(`${RELAY}/inbox`);
		expect(response.status).toBe(200);
		const document = (await response.json()) as Record<string, unknown>;
		expect(document.id).toBe(`${RELAY}/inbox`);
		expect(document.type).toBe('OrderedCollection');
	});

	it('serves status.json schema version 5', async () => {
		const response = await SELF.fetch(`${RELAY}/status.json`);
		expect(response.status).toBe(200);
		expect(response.headers.get('cache-control')).toBe('public, max-age=30');
		const status = (await response.json()) as Record<string, any>;
		expect(status.schema_version).toBe(5);
		expect(status.status).toBe('ok');
		expect(status.domain).toBe('relay.manalejandro.com');
		expect(status.registration).toBe('open');
		expect(status.public_address_distribution_policy).toBe('explicit_public_only');
		expect(status.endpoints).toEqual({ inbox: `${RELAY}/inbox`, actor: `${RELAY}/actor` });
		expect(status.connected_instances).toEqual({ count: 0, domains: [] });
		expect(status.receiving_instances.count).toBe(0);
		expect(status.publishers.count).toBe(0);
		expect(status.software.name).toBe('cf-activity-relay');
		expect(JSON.stringify(status)).not.toContain('inbox_url');
	});

	it('serves WebFinger for the relay account', async () => {
		const response = await SELF.fetch(`${RELAY}/.well-known/webfinger?resource=acct:relay@relay.manalejandro.com`);
		expect(response.status).toBe(200);
		const document = (await response.json()) as Record<string, any>;
		expect(document.subject).toBe('acct:relay@relay.manalejandro.com');
		expect(document.links[0]).toEqual({ rel: 'self', type: 'application/activity+json', href: `${RELAY}/actor` });
	});

	it('rejects unknown WebFinger resources', async () => {
		const response = await SELF.fetch(`${RELAY}/.well-known/webfinger?resource=acct:someone@elsewhere.example`);
		expect(response.status).toBe(404);
	});

	it('serves NodeInfo discovery and 2.1 documents', async () => {
		const discovery = await SELF.fetch(`${RELAY}/.well-known/nodeinfo`);
		expect(discovery.status).toBe(200);
		const links = (await discovery.json()) as Record<string, any>;
		expect(links.links[0].href).toBe(`${RELAY}/nodeinfo/2.1`);

		const nodeinfo = await SELF.fetch(`${RELAY}/nodeinfo/2.1`);
		expect(nodeinfo.status).toBe(200);
		const document = (await nodeinfo.json()) as Record<string, any>;
		expect(document.version).toBe('2.1');
		expect(document.software.name).toBe('cf-activity-relay');
		expect(document.protocols).toEqual(['activitypub']);
	});

	it('answers health checks and unknown paths', async () => {
		expect((await SELF.fetch(`${RELAY}/health`)).status).toBe(200);
		expect((await SELF.fetch(`${RELAY}/does-not-exist`)).status).toBe(404);
	});
});
