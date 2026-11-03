/**
 * In-memory store of presentation requests.
 *
 * A request lives for the login attempt's lifetime plus a grace period (the
 * plugin's `/complete` retries for a short while after the chain says
 * "verified"), then it is deleted with its result. Correlation ids are
 * remembered for a day so the same one is never accepted twice while the
 * plugin could still hold the attempt.
 */

export type RequestState = 'pending' | 'settling' | 'verified' | 'rejected' | 'failed';

export interface PresentationResult {
  subject_id: string;
  issuer: string | null;
  presentation_hash: string;
  claims: Record<string, unknown>;
}

export interface AttestationRecord {
  result: 1 | 2;
  subjectCommitment: string;
  presentationHash: string;
  fireflyOperation: string | null;
  fireflyTransaction: string | null;
}

export interface BridgeRequest {
  id: string;
  correlationId: string;
  nonce: string;
  /** 64 hex characters from WordPress; enters the subject commitment and nothing else. */
  blindingSecret: string;
  query: string;
  /** Unix time in milliseconds after which the verifier refuses wallet responses. */
  expiresAt: number;
  createdAt: number;
  /** Bearer token the verifier must present on callbacks for this request. */
  callbackToken: string;
  state: RequestState;
  /** A callback arrived but the verifier session could not be read: the next sweep tries again. */
  recheck: boolean;
  result: PresentationResult | null;
  attestation: AttestationRecord | null;
}

export const RESULT_GRACE_MS = 60_000;
const CORRELATION_MEMORY_MS = 24 * 60 * 60 * 1000;

export class RequestStore {
  private readonly requests = new Map<string, BridgeRequest>();
  private readonly correlations = new Map<string, number>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly resultGraceMs: number = RESULT_GRACE_MS,
  ) {}

  /** Claims a correlation id. Returns false when it was seen in the last day. */
  reserveCorrelation(correlationId: string): boolean {
    if (this.correlations.has(correlationId)) {
      return false;
    }
    this.correlations.set(correlationId, this.now());
    return true;
  }

  releaseCorrelation(correlationId: string): void {
    this.correlations.delete(correlationId);
  }

  add(request: BridgeRequest): void {
    if (this.requests.has(request.id)) {
      throw new Error(`Request ${request.id} already exists`);
    }
    this.requests.set(request.id, request);
  }

  get(id: string): BridgeRequest | undefined {
    return this.requests.get(id);
  }

  get size(): number {
    return this.requests.size;
  }

  /** Pending requests whose last callback could not be acted on. */
  needingRecheck(): BridgeRequest[] {
    return [...this.requests.values()].filter((request) => request.state === 'pending' && request.recheck);
  }

  /** Deletes requests past their lifetime plus grace, and forgets correlation ids older than a day. */
  sweep(): number {
    const now = this.now();
    let removed = 0;
    for (const [id, request] of this.requests) {
      if (request.expiresAt + this.resultGraceMs <= now) {
        this.requests.delete(id);
        removed++;
      }
    }
    for (const [correlationId, seenAt] of this.correlations) {
      if (seenAt + CORRELATION_MEMORY_MS <= now) {
        this.correlations.delete(correlationId);
      }
    }
    return removed;
  }
}
