import { describe, expect, it } from 'vitest';
import { asStringArray, hostOf, isDeliverableUrl, isPrivateHost, normalizeDomain, normalizeOrigin, objectId, parseHttpUrl, stripFragment } from '../src/utils/domains';

describe('domain helpers', () => {
	it('normalizes hostnames', () => {
		expect(normalizeDomain('Example.COM.')).toBe('example.com');
		expect(normalizeDomain('  relay.example.org ')).toBe('relay.example.org');
		expect(normalizeDomain('')).toBe('');
	});

	it('extracts hosts from URLs', () => {
		expect(hostOf('https://Relay.Example.org/inbox')).toBe('relay.example.org');
		expect(hostOf('https://example.org:8443/inbox')).toBe('example.org');
		expect(hostOf('not a url')).toBe('');
	});

	it('parses only credential-free HTTP(S) URLs', () => {
		expect(parseHttpUrl('https://example.org/actor')?.hostname).toBe('example.org');
		expect(parseHttpUrl('ftp://example.org')).toBeNull();
		expect(parseHttpUrl('https://user:pass@example.org')).toBeNull();
		expect(parseHttpUrl('not a url')).toBeNull();
	});

	it('strips fragments', () => {
		expect(stripFragment('https://example.org/actor#main-key')).toBe('https://example.org/actor');
		expect(stripFragment('https://example.org/actor')).toBe('https://example.org/actor');
	});

	it('blocks private and loopback hosts', () => {
		expect(isPrivateHost('localhost')).toBe(true);
		expect(isPrivateHost('10.1.2.3')).toBe(true);
		expect(isPrivateHost('192.168.0.5')).toBe(true);
		expect(isPrivateHost('172.16.4.2')).toBe(true);
		expect(isPrivateHost('169.254.169.254')).toBe(true);
		expect(isPrivateHost('example.org')).toBe(false);
		expect(isPrivateHost('172.32.0.1')).toBe(false);
	});

	it('validates deliverable URLs', () => {
		expect(isDeliverableUrl('https://example.org/inbox')).toBe(true);
		expect(isDeliverableUrl('https://localhost/inbox')).toBe(false);
		expect(isDeliverableUrl('not-a-url')).toBe(false);
	});

	it('canonicalizes origins', () => {
		expect(normalizeOrigin('https://Example.org:443/inbox')).toBe('https://example.org');
		expect(normalizeOrigin('http://example.org:8080/inbox')).toBe('http://example.org:8080');
		expect(normalizeOrigin('not-a-url')).toBeNull();
	});

	it('normalizes audience values and object identifiers', () => {
		expect(asStringArray('https://example.org/actor')).toEqual(['https://example.org/actor']);
		expect(asStringArray(['a', 'b'])).toEqual(['a', 'b']);
		expect(asStringArray(undefined)).toEqual([]);
		expect(objectId('https://example.org/notes/1')).toBe('https://example.org/notes/1');
		expect(objectId({ id: 'https://example.org/notes/2' })).toBe('https://example.org/notes/2');
		expect(objectId({})).toBeNull();
	});
});
