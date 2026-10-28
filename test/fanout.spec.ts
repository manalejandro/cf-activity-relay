import { describe, expect, it } from 'vitest';
import { selectTargets } from '../src/ap/fanout';
import type { Receiver } from '../src/types';

function receiver(domain: string, inboxUrl: string, kind: 'subscriber' | 'follower' = 'subscriber'): Receiver {
	return { domain, inboxUrl, activityId: `https://${domain}/activities/follow`, actorId: `https://${domain}/actor`, kind, mutuallyFollow: true };
}

describe('fan-out target selection', () => {
	it('prefers the traditional subscriber route for overlapping domains', () => {
		const targets = selectTargets(
			[receiver('a.example', 'https://a.example/inbox'), receiver('a.example', 'https://a.example/actor/inbox', 'follower')],
			[],
		);
		expect(targets).toHaveLength(1);
		expect(targets[0].kind).toBe('subscriber');
		expect(targets[0].inboxUrl).toBe('https://a.example/inbox');
	});

	it('excludes the publishing source and other supplied domains', () => {
		const targets = selectTargets(
			[receiver('source.example', 'https://source.example/inbox'), receiver('other.example', 'https://other.example/inbox'), receiver('keep.example', 'https://keep.example/inbox')],
			['source.example', 'other.example'],
		);
		expect(targets.map((target) => target.domain)).toEqual(['keep.example']);
	});

	it('skips receivers with invalid or private inbox URLs', () => {
		const targets = selectTargets(
			[receiver('bad.example', 'not-a-url'), receiver('local.example', 'https://localhost/inbox'), receiver('good.example', 'https://good.example/inbox')],
			[],
		);
		expect(targets.map((target) => target.domain)).toEqual(['good.example']);
	});

	it('skips silenced (blocked or limited) domains', () => {
		const targets = selectTargets(
			[receiver('blocked.example', 'https://blocked.example/inbox'), receiver('limited.example', 'https://limited.example/inbox', 'follower'), receiver('ok.example', 'https://ok.example/inbox')],
			[],
			new Set(['blocked.example', 'limited.example']),
		);
		expect(targets.map((target) => target.domain)).toEqual(['ok.example']);
	});

	it('normalizes domain casing and trailing dots before de-duplicating', () => {
		const targets = selectTargets([receiver('A.Example.', 'https://a.example/inbox'), receiver('a.example', 'https://a.example/other-inbox')], []);
		expect(targets).toHaveLength(1);
		expect(targets[0].domain).toBe('a.example');
	});
});
