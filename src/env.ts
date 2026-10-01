/**
 * Worker bindings and configuration variables.
 *
 * Bindings (D1, KV, Queues, static assets) are declared in `wrangler.jsonc`.
 * Plain variables are declared under `vars`; secrets such as `ADMIN_TOKEN` and
 * the optional `RELAY_PRIVATE_KEY_PEM` are uploaded with `wrangler secret put`.
 */
export interface Env {
	/** Durable relay state: subscriptions, publishers, configuration, queues. */
	DB: D1Database;
	/** Short-lived cache for remote actor documents and capability evidence. */
	CACHE: KVNamespace;
	/** Fan-out delivery queue. */
	DELIVERY_QUEUE: Queue<DeliveryMessage>;
	/** Static assets: landing page, logo and banner. */
	ASSETS: Fetcher;

	/** Public hostname of the relay, for example `relay.example.org`. */
	RELAY_DOMAIN?: string;
	/** Human readable relay name advertised in the actor document. */
	RELAY_SERVICENAME?: string;
	/** Long description advertised in the actor document. */
	RELAY_SUMMARY?: string;
	/** Square logo URL advertised in the actor document. */
	RELAY_ICON?: string;
	/** Wide banner URL advertised in the actor document. */
	RELAY_IMAGE?: string;
	/** `explicit_public_only` (default) or `public_and_unlisted`. */
	PUBLIC_ADDRESS_DISTRIBUTION_POLICY?: string;
	/** `dual` (default), `legacy` or `rfc9421`. */
	OUTBOUND_SIGNATURE_PROFILE?: string;
	/** When `true`, only `Person` actors may publish through the relay. */
	PERSON_ONLY?: string;
	/** When `true`, new subscriptions require manual approval. */
	MANUALLY_ACCEPT?: string;
	/** Maximum accepted inbound activity size in bytes. Default 1048576. */
	MAX_ACTIVITY_BYTES?: string;
	/** Maximum number of fan-out targets per activity. Default 5000. */
	MAX_FANOUT_TARGETS?: string;
	/** Maximum number of queued fan-out payloads. Default 100000. */
	MAX_QUEUE_JOBS?: string;
	/** Optional comma separated list of domains blocked at startup. */
	BLOCKED_DOMAINS?: string;
	/** Optional comma separated list of limited domains at startup. */
	LIMITED_DOMAINS?: string;

	/** Bearer token protecting the `/admin` API. When unset the API is disabled. */
	ADMIN_TOKEN?: string;
	/** Optional externally managed PKCS#8/PKCS#1 RSA private key in PEM form. */
	RELAY_PRIVATE_KEY_PEM?: string;
}

/** A single fan-out delivery task. */
export interface DeliveryMessage {
	v: 1;
	/** Destination shared inbox. */
	inboxUrl: string;
	/** Identifier of the shared payload row in D1 (`activity_payloads.id`). */
	payloadId: string;
	/** Wire signature profile chosen before queueing: `legacy` or `rfc9421`. */
	profile: 'legacy' | 'rfc9421';
}
