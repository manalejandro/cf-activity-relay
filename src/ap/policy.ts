import { PUBLIC_ADDRESS, type PublicAddressPolicy } from '../config';

/**
 * Public-address distribution policy.
 *
 * `explicit_public_only` distributes activities only when the ActivityStreams
 * Public collection appears in the primary `to` audience.
 * `public_and_unlisted` also accepts Public from `cc`.
 */
export function allowsPublicAddress(to: string[], cc: string[], policy: PublicAddressPolicy): boolean {
	if (to.includes(PUBLIC_ADDRESS)) return true;
	return policy === 'public_and_unlisted' && cc.includes(PUBLIC_ADDRESS);
}

/** True when Public appears only in `cc` under the strict policy. */
export function excludesPublicOnlyInCc(to: string[], cc: string[], policy: PublicAddressPolicy): boolean {
	return policy === 'explicit_public_only' && !to.includes(PUBLIC_ADDRESS) && cc.includes(PUBLIC_ADDRESS);
}
