import type { RelayConfig } from '../config';
import type { Env } from '../env';
import { generateRsaKeyPair, importPrivateKey, isPrivateKeyPem, publicKeyPemFromPrivate } from '../crypto/keys';
import { getStoredIdentity, storeIdentity } from '../store/repo';

export interface RelayIdentity {
	privateKeyPem: string;
	publicKeyPem: string;
	actorId: string;
	keyId: string;
}

let cached: RelayIdentity | null = null;
let pending: Promise<RelayIdentity> | null = null;

/**
 * Loads the relay RSA identity, generating and persisting it on first use.
 *
 * The key is stored in D1 so that every deployment keeps a stable federation
 * identity without operator interaction. An operator may instead supply
 * `RELAY_PRIVATE_KEY_PEM` as a secret; the derived public key is persisted.
 */
export async function getRelayIdentity(env: Env, config: RelayConfig): Promise<RelayIdentity> {
	if (cached) return cached;
	if (pending) return pending;
	pending = (async () => {
		let stored = await getStoredIdentity(env.DB);
		if (!stored) {
			const supplied = env.RELAY_PRIVATE_KEY_PEM;
			const generated = isPrivateKeyPem(supplied)
				? { privateKeyPem: supplied as string, publicKeyPem: await publicKeyPemFromPrivate(supplied as string) }
				: await generateRsaKeyPair(2048);
			await storeIdentity(env.DB, generated);
			stored = (await getStoredIdentity(env.DB)) ?? generated;
		}
		// Fail fast when the persisted material is unusable.
		await importPrivateKey(stored.privateKeyPem);
		cached = { privateKeyPem: stored.privateKeyPem, publicKeyPem: stored.publicKeyPem, actorId: config.actorId, keyId: config.keyId };
		return cached;
	})().finally(() => {
		pending = null;
	});
	return pending;
}

/** Clears the per-isolate identity cache (used by tests). */
export function resetIdentityCache(): void {
	cached = null;
	pending = null;
}
