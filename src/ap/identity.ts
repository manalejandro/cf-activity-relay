import type { RelayConfig } from '../config';
import type { Env } from '../env';
import { generateRsaKeyPair, importPrivateKey, isPrivateKeyPem, publicKeyPemFromPrivate } from '../crypto/keys';
import { getStoredIdentity, setIdentity, storeIdentity } from '../store/repo';

export interface RelayIdentity {
	privateKeyPem: string;
	publicKeyPem: string;
	actorId: string;
	keyId: string;
}

let cached: RelayIdentity | null = null;
let pending: Promise<RelayIdentity> | null = null;

/**
 * Loads the relay RSA identity.
 *
 * An operator supplied `RELAY_PRIVATE_KEY_PEM` secret always wins: when it is
 * present (or rotated) the derived public key replaces the stored pair, so
 * uploading a new secret actually changes the federation identity. Without a
 * secret the key is generated once and persisted in D1 so that every
 * deployment keeps a stable identity without operator interaction.
 */
export async function getRelayIdentity(env: Env, config: RelayConfig): Promise<RelayIdentity> {
	if (cached) return cached;
	if (pending) return pending;
	pending = (async () => {
		const supplied = env.RELAY_PRIVATE_KEY_PEM;
		let privateKeyPem: string;
		let publicKeyPem: string;
		if (isPrivateKeyPem(supplied)) {
			privateKeyPem = supplied as string;
			publicKeyPem = await publicKeyPemFromPrivate(privateKeyPem);
			const stored = await getStoredIdentity(env.DB);
			if (!stored || stored.privateKeyPem !== privateKeyPem) {
				await setIdentity(env.DB, { privateKeyPem, publicKeyPem });
				console.log('relay identity updated from RELAY_PRIVATE_KEY_PEM secret');
			}
		} else {
			let stored = await getStoredIdentity(env.DB);
			if (!stored) {
				const generated = await generateRsaKeyPair(2048);
				await storeIdentity(env.DB, generated);
				stored = (await getStoredIdentity(env.DB)) ?? generated;
			}
			privateKeyPem = stored.privateKeyPem;
			publicKeyPem = stored.publicKeyPem;
		}
		// Fail fast when the persisted material is unusable.
		await importPrivateKey(privateKeyPem);
		cached = { privateKeyPem, publicKeyPem, actorId: config.actorId, keyId: config.keyId };
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
