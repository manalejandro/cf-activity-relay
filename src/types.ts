/** Minimal ActivityStreams activity representation used by the relay. */
export interface APActivity {
	'@context'?: unknown;
	id?: string;
	type: string;
	actor?: string;
	object?: unknown;
	to?: string | string[];
	cc?: string | string[];
	[key: string]: unknown;
}

/** A remote actor document reduced to the fields the relay needs. */
export interface RemoteActor {
	id: string;
	type: string;
	inbox?: string;
	sharedInbox?: string;
	preferredUsername?: string;
	publicKeyId?: string;
	publicKeyPem?: string;
	publicKeyOwner?: string;
	/** Raw actor document, kept for diagnostics and future use. */
	raw: Record<string, unknown>;
}

/** Subscription record shared by traditional and follower-style receivers. */
export interface Receiver {
	domain: string;
	inboxUrl: string;
	activityId: string;
	actorId: string;
	/** `subscriber` for `/inbox` style, `follower` for `/actor` style. */
	kind: 'subscriber' | 'follower';
	mutuallyFollow: boolean;
}

/** Publisher observed while relaying public traffic. */
export interface Publisher {
	domain: string;
	actorId: string;
	inboxUrl: string | null;
	firstSeen: string;
	lastSeen: string;
	lastActivityId: string | null;
	lastActivityType: string | null;
	activityCount: number;
}

/** Delivery health counters for a receiving instance. */
export interface ReceiverHealth {
	domain: string;
	lastSuccessAt: string | null;
	lastFailureAt: string | null;
	consecutiveFailures: number;
	totalSuccesses: number;
	totalFailures: number;
}

/** Pending manual-approval request. */
export interface PendingRequest {
	domain: string;
	inboxUrl: string;
	activityId: string;
	type: string;
	actor: string;
	object: string;
	createdAt: string;
}

/** Relay runtime settings persisted in D1 and editable through the admin API. */
export interface RelaySettings {
	personOnly: boolean;
	manuallyAccept: boolean;
}
