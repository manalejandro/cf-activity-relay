/**
 * Queue consumer: signs and delivers queued activities with bounded retries.
 *
 * A shared payload row is decremented only on terminal success or final
 * exhaustion, so one failing receiver can never delete the body needed by
 * another receiver or by its own delayed retry.
 */
import { DELIVERY_MAX_ATTEMPTS, DELIVERY_RETRY_DELAYS, DELIVERY_TIMEOUT_MS, MAX_ERROR_BODY_BYTES, loadConfig, type RelayConfig } from '../config';
import { signLegacyRequest } from '../crypto/legacy';
import { signRfc9421Request } from '../crypto/rfc9421';
import type { DeliveryMessage, Env } from '../env';
import { decrementPayload, getPayload, recordReceiverFailure, recordReceiverSuccess } from '../store/repo';
import { hostOf, isDeliverableUrl } from '../utils/domains';
import { readBoundedText } from '../utils/http';
import type { RelayIdentity } from './identity';
import { getRelayIdentity } from './identity';

function isPermanentStatus(status: number): boolean {
	if (status >= 300 && status < 400) return true;
	if (status === 408 || status === 429) return false;
	return status >= 400 && status < 500;
}

async function ignoreFailure(action: () => Promise<void>): Promise<void> {
	try {
		await action();
	} catch (error) {
		console.error('delivery bookkeeping failed', { error: error instanceof Error ? error.message : String(error) });
	}
}

async function deliverOne(env: Env, config: RelayConfig, identity: RelayIdentity, message: Message<DeliveryMessage>): Promise<void> {
	const task = message.body;
	if (!task || task.v !== 1 || !isDeliverableUrl(task.inboxUrl)) {
		message.ack();
		return;
	}
	const payload = await getPayload(env.DB, task.payloadId);
	if (!payload) {
		message.ack();
		return;
	}
	const domain = hostOf(task.inboxUrl);
	const startedAt = Date.now();
	let response: Response | null = null;
	let errorText: string | null = null;
	try {
		const signing =
			task.profile === 'legacy'
				? await signLegacyRequest({ method: 'POST', url: task.inboxUrl, body: payload.body, privateKeyPem: identity.privateKeyPem, keyId: identity.keyId })
				: await signRfc9421Request({ method: 'POST', url: task.inboxUrl, body: payload.body, privateKeyPem: identity.privateKeyPem, keyId: identity.keyId });
		response = await fetch(task.inboxUrl, {
			method: 'POST',
			headers: { ...signing },
			body: payload.body,
			redirect: 'manual',
			signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
		});
	} catch (error) {
		errorText = error instanceof Error ? error.message : 'network error';
	}

	if (response?.ok) {
		await ignoreFailure(() => recordReceiverSuccess(env.DB, domain));
		await decrementPayload(env.DB, task.payloadId);
		message.ack();
		console.log('delivery succeeded', { domain, status: response.status, profile: task.profile, elapsedMs: Date.now() - startedAt });
		return;
	}

	const status = response?.status ?? 0;
	const responseText = response ? await readBoundedText(response, MAX_ERROR_BODY_BYTES) : '';
	const permanent = response !== null && isPermanentStatus(status);
	if (permanent || message.attempts >= DELIVERY_MAX_ATTEMPTS) {
		await ignoreFailure(() => recordReceiverFailure(env.DB, domain));
		await decrementPayload(env.DB, task.payloadId);
		message.ack();
		console.warn('delivery failed permanently', {
			domain,
			status,
			profile: task.profile,
			attempts: message.attempts,
			error: errorText ?? responseText,
		});
		return;
	}

	const delay = DELIVERY_RETRY_DELAYS[Math.min(message.attempts, DELIVERY_RETRY_DELAYS.length) - 1];
	console.log('delivery scheduled for retry', { domain, status, attempts: message.attempts, delaySeconds: delay, error: errorText ?? responseText });
	message.retry({ delaySeconds: delay });
}

async function handleDeadLetter(env: Env, message: Message<DeliveryMessage>): Promise<void> {
	const task = message.body;
	if (!task?.payloadId) {
		message.ack();
		return;
	}
	await ignoreFailure(() => recordReceiverFailure(env.DB, hostOf(task.inboxUrl)));
	await ignoreFailure(() => decrementPayload(env.DB, task.payloadId));
	console.warn('delivery moved to dead-letter queue', { inbox: task.inboxUrl, profile: task.profile });
	message.ack();
}

/** Entry point for both the delivery queue and its dead-letter queue. */
export async function consumeDeliveryBatch(batch: MessageBatch<DeliveryMessage>, env: Env): Promise<void> {
	const config = loadConfig(env);
	const identity = await getRelayIdentity(env, config);
	const deadLetter = batch.queue.endsWith('-dlq');
	for (const message of batch.messages) {
		if (deadLetter) {
			await handleDeadLetter(env, message);
			continue;
		}
		await deliverOne(env, config, identity, message);
	}
}
