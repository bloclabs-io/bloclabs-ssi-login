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
  /**
   * The credential's `exp` as ISO 8601, when it is an SD-JWT VC NumericDate.
   * Absent when the credential names no usable expiry. A verified agent result
   * always has it: the agent query refuses a credential that does not.
   */
  expires_at?: string;
}

export interface AttestationRecord {
  result: 1 | 2;
  subjectCommitment: string;
  presentationHash: string;
  fireflyOperation: string | null;
  fireflyTransaction: string | null;
}

/** The second verifier session of a request, for the Digital Credentials API path. */
export interface DcApiSession {
  sessionId: string;
}

export interface BridgeRequest {
  /** The bridge's id for the request, also the id of its cross-device verifier session. */
  id: string;
  correlationId: string;
  nonce: string;
  /** 64 hex characters from WordPress; enters the subject commitment and nothing else. */
  blindingSecret: string;
  query: string;
  /** Unix time in milliseconds after which the verifier refuses wallet responses. */
  expiresAt: number;
  createdAt: number;
  /** Bearer token the verifier must present on callbacks for this request's sessions. */
  callbackToken: string;
  /** Set while the request also has a `dc_api_openid4vp` session; either session may settle it. */
  dcApi: DcApiSession | null;
  state: RequestState;
  /**
   * Verifier sessions of this request whose last callback could not be acted on
   * (the session could not be read): the next sweep reads each of them again.
   * Kept per session, so a good read of one session cannot forget the other's retry.
   */
  recheck: Set<string>;
  result: PresentationResult | null;
  attestation: AttestationRecord | null;
}

export const RESULT_GRACE_MS = 60_000;
const CORRELATION_MEMORY_MS = 24 * 60 * 60 * 1000;

/** The verifier session ids of a request: the cross-device one, then the Digital Credentials API one. */
export function sessionIdsOf(request: BridgeRequest): string[] {
  return request.dcApi ? [request.id, request.dcApi.sessionId] : [request.id];
}

export class RequestStore {
  private readonly requests = new Map<string, BridgeRequest>();
  /** Verifier session id to request id, for callbacks: a request may have two sessions. */
  private readonly sessions = new Map<string, string>();
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
    for (const sessionId of sessionIdsOf(request)) {
      if (this.sessions.has(sessionId)) {
        throw new Error(`Session ${sessionId} already belongs to a request`);
      }
    }
    this.requests.set(request.id, request);
    for (const sessionId of sessionIdsOf(request)) {
      this.sessions.set(sessionId, request.id);
    }
  }

  get(id: string): BridgeRequest | undefined {
    return this.requests.get(id);
  }

  /** The request a verifier session belongs to. */
  findBySession(sessionId: string): BridgeRequest | undefined {
    const id = this.sessions.get(sessionId);
    return id === undefined ? undefined : this.requests.get(id);
  }

  /** Detaches a Digital Credentials API session the browser will never get the request for. */
  dropDcApiSession(request: BridgeRequest): void {
    if (request.dcApi) {
      this.sessions.delete(request.dcApi.sessionId);
      request.recheck.delete(request.dcApi.sessionId);
      request.dcApi = null;
    }
  }

  get size(): number {
    return this.requests.size;
  }

  /** Pending requests whose last callback could not be acted on. */
  needingRecheck(): BridgeRequest[] {
    return [...this.requests.values()].filter((request) => request.state === 'pending' && request.recheck.size > 0);
  }

  /** Deletes requests past their lifetime plus grace, and forgets correlation ids older than a day. */
  sweep(): number {
    const now = this.now();
    let removed = 0;
    for (const [id, request] of this.requests) {
      if (request.expiresAt + this.resultGraceMs <= now) {
        this.requests.delete(id);
        for (const sessionId of sessionIdsOf(request)) {
          this.sessions.delete(sessionId);
        }
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
