import { describe, expect, it } from 'vitest';
import { PUBLIC_ADDRESS } from '../src/config';
import { allowsPublicAddress, excludesPublicOnlyInCc } from '../src/ap/policy';

const OTHER = 'https://www.w3.org/ns/activitystreams#Other';

describe('public address distribution policy', () => {
	it('distributes when Public is in to', () => {
		expect(allowsPublicAddress([PUBLIC_ADDRESS], [], 'explicit_public_only')).toBe(true);
		expect(allowsPublicAddress([PUBLIC_ADDRESS], [], 'public_and_unlisted')).toBe(true);
	});

	it('distributes Public in cc only under the permissive policy', () => {
		expect(allowsPublicAddress([OTHER], [PUBLIC_ADDRESS], 'explicit_public_only')).toBe(false);
		expect(allowsPublicAddress([OTHER], [PUBLIC_ADDRESS], 'public_and_unlisted')).toBe(true);
	});

	it('never distributes followers-only or direct activities', () => {
		expect(allowsPublicAddress(['https://example.org/actor/followers'], [], 'public_and_unlisted')).toBe(false);
		expect(allowsPublicAddress(['https://example.org/actor'], [], 'public_and_unlisted')).toBe(false);
	});

	it('flags Public only in cc for the strict policy', () => {
		expect(excludesPublicOnlyInCc([OTHER], [PUBLIC_ADDRESS], 'explicit_public_only')).toBe(true);
		expect(excludesPublicOnlyInCc([OTHER], [PUBLIC_ADDRESS], 'public_and_unlisted')).toBe(false);
		expect(excludesPublicOnlyInCc([PUBLIC_ADDRESS], [PUBLIC_ADDRESS], 'explicit_public_only')).toBe(false);
	});
});
