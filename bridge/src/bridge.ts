/**
 * The bridge's behaviour, independent of HTTP:
 *
 *  1. WordPress opens a presentation request; the bridge opens a verifier session
 *     for it and hands back the wallet URL.
 *  2. The verifier rings the bridge's callback for every session update. The
 *     bridge re-reads the session and, once it is SUCCESSFUL or FAILED, computes
 *     the commitments and calls `attest` through FireFly.
 *  3. Only after FireFly accepted the attestation does the result become readable,
 *     and it stays readable for the attempt lifetime plus a minute.
 */

import type { Config } from './config.js';
import { isRecord } from './config.js';
import { ZERO_HASH, constantTimeEqual, newRequestId, randomToken, subjectCommitment } from './crypto.js';
import type { AttestInput, AttestOutcome, FireFlyClient } from './firefly.js';
import { FireFlyError } from './firefly.js';
import type { Logger } from './log.js';
import type { BridgeRequest, RequestStore } from './store.js';
import { RESULT_GRACE_MS } from './store.js';
import type { Evaluation, VerifierClient } from './verifier.js';
import { buildSessionSetup, evaluateSession } from './verifier.js';

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail?: string,
  ) {
    super(detail ?? code);
  }

  body(): Record<string, string> {
    return this.detail === undefined ? { error: this.code } : { error: this.code, detail: this.detail };
  }
}

export interface BridgeOptions {
  config: Config;
  store: RequestStore;
  verifier: VerifierClient;
  firefly: FireFlyClient;
  log: Logger;
  now?: () => number;
  /** Waits between attestation attempts; one more attempt than there are delays. */
  attestRetryDelaysMs?: number[];
  sleep?: (ms: number) => Promise<void>;
}

export interface CreatedRequest {
  id: string;
  wallet_url: string;
  dc_api: null;
}

const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_NONCE_LENGTH = 512;

export class Bridge {
  private readonly config: Config;
  private readonly store: RequestStore;
  private readonly verifier: VerifierClient;
  private readonly firefly: FireFlyClient;
  private readonly log: Logger;
  private readonly now: () => number;
  private readonly attestRetryDelaysMs: number[];
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly checks = new Map<string, { again: boolean }>();
  private idleWaiters: Array<() => void> = [];

  constructor(options: BridgeOptions) {
    this.config = options.config;
    this.store = options.store;
    this.verifier = options.verifier;
    this.firefly = options.firefly;
    this.log = options.log;
    this.now = options.now ?? Date.now;
    this.attestRetryDelaysMs = options.attestRetryDelaysMs ?? [1_000, 3_000];
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  /** POST /v1/presentation-requests */
  async createRequest(body: unknown): Promise<CreatedRequest> {
    if (!isRecord(body)) {
      throw new HttpError(400, 'invalid_request', 'The body must be a JSON object');
    }
    const correlationId = typeof body['correlation_id'] === 'string' ? body['correlation_id'].toLowerCase() : '';
    if (!/^[0-9a-f]{64}$/.test(correlationId)) {
      throw new HttpError(400, 'invalid_request', 'correlation_id must be 64 hex characters');
    }
    const nonce = body['nonce'];
    if (typeof nonce !== 'string' || nonce === '' || nonce.length > MAX_NONCE_LENGTH) {
      throw new HttpError(400, 'invalid_request', 'nonce must be a non-empty string');
    }
    const blindingSecret = typeof body['blinding_secret'] === 'string' ? body['blinding_secret'].toLowerCase() : '';
    if (!/^[0-9a-f]{64}$/.test(blindingSecret)) {
      throw new HttpError(400, 'invalid_request', 'blinding_secret must be 64 hex characters');
    }
    const queryName = body['query'];
    if (typeof queryName !== 'string' || !Object.hasOwn(this.config.queries, queryName)) {
      throw new HttpError(400, 'unknown_query', 'query must name a query configured in the bridge');
    }
    const query = this.config.queries[queryName]!;
    const expiresAt = typeof body['expires_at'] === 'string' ? Date.parse(body['expires_at']) : Number.NaN;
    const now = this.now();
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      throw new HttpError(400, 'invalid_request', 'expires_at must be an ISO 8601 time in the future');
    }
    if (expiresAt - now > MAX_LIFETIME_MS) {
      throw new HttpError(400, 'invalid_request', 'expires_at is more than a day away');
    }

    if (!this.store.reserveCorrelation(correlationId)) {
      throw new HttpError(409, 'duplicate_correlation_id', 'This correlation_id was already used');
    }

    const id = newRequestId();
    const callbackToken = randomToken();
    const setup = buildSessionSetup({
      id,
      query,
      expiresAt: new Date(expiresAt),
      retainUntil: new Date(expiresAt + RESULT_GRACE_MS),
      webhookUrl: `${this.config.callbackUrl}/${id}`,
      webhookToken: callbackToken,
    });

    let created;
    try {
      created = await this.verifier.createSession(setup);
    } catch (error) {
      this.store.releaseCorrelation(correlationId);
      // Nothing was stored for this id, so the verifier's message cannot leak a usable token.
      this.log.error('could not open a verifier session', { id, query: queryName, error: (error as Error).message });
      throw new HttpError(502, 'verifier_unavailable');
    }
    if (created.sessionId !== id) {
      this.store.releaseCorrelation(correlationId);
      this.log.error('the verifier ignored the requested session id', { id, query: queryName });
      throw new HttpError(502, 'verifier_unavailable');
    }

    this.store.add({
      id,
      correlationId,
      nonce,
      blindingSecret,
      query: queryName,
      expiresAt,
      createdAt: now,
      callbackToken,
      state: 'pending',
      result: null,
      attestation: null,
    });
    this.log.info('presentation request opened', { id, query: queryName, expiresAt: new Date(expiresAt).toISOString() });
    return { id, wallet_url: created.walletUrl, dc_api: null };
  }

  /**
   * POST /v1/verifier-callbacks/{id}: the verifier's doorbell. Authenticated by the
   * per-request bearer token the bridge gave the verifier; the body is ignored.
   */
  handleCallback(id: string, authorization: string | undefined): 'accepted' | 'unauthorized' | 'unknown' {
    const request = this.store.get(id);
    if (!request) {
      return 'unknown';
    }
    if (authorization === undefined || !constantTimeEqual(authorization, `Bearer ${request.callbackToken}`)) {
      this.log.warn('callback with a bad token', { id });
      return 'unauthorized';
    }
    this.scheduleCheck(id);
    return 'accepted';
  }

  /** GET /v1/presentation-requests/{id}/result */
  getResult(id: string): { status: number; body: unknown } {
    const request = this.store.get(id);
    if (!request) {
      return { status: 404, body: { error: 'not_found' } };
    }
    switch (request.state) {
      case 'verified':
        return { status: 200, body: request.result };
      case 'rejected':
        return { status: 404, body: { error: 'rejected' } };
      case 'failed':
        return { status: 404, body: { error: 'failed' } };
      default:
        return { status: 409, body: { error: 'pending' } };
    }
  }

  sweep(): number {
    const removed = this.store.sweep();
    if (removed > 0) {
      this.log.debug('expired requests deleted', { count: removed });
    }
    return removed;
  }

  /** Resolves once no callback is being processed; for tests and shutdown. */
  idle(): Promise<void> {
    if (this.checks.size === 0) {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.idleWaiters.push(resolve);
    });
  }

  private scheduleCheck(id: string): void {
    const running = this.checks.get(id);
    if (running) {
      running.again = true;
      return;
    }
    const entry = { again: false };
    this.checks.set(id, entry);
    void (async () => {
      try {
        do {
          entry.again = false;
          try {
            await this.check(id);
          } catch (error) {
            this.log.error('processing a verifier callback crashed', { id, error: (error as Error).message });
          }
        } while (entry.again);
      } finally {
        this.checks.delete(id);
        if (this.checks.size === 0) {
          const waiters = this.idleWaiters;
          this.idleWaiters = [];
          waiters.forEach((resolve) => resolve());
        }
      }
    })();
  }

  private async check(id: string): Promise<void> {
    const request = this.store.get(id);
    if (!request || request.state !== 'pending') {
      return;
    }
    let session;
    try {
      session = await this.verifier.getSession(id);
    } catch (error) {
      this.log.warn('could not read the verifier session', { id, error: (error as Error).message });
      return;
    }
    const evaluation = evaluateSession(session, this.config.queries[request.query]!);
    if (evaluation.kind === 'undecided') {
      this.log.debug('verifier session still undecided', { id, status: evaluation.status });
      return;
    }
    if (evaluation.kind === 'inconsistent') {
      request.state = 'failed';
      this.log.error('verifier session cannot be used', { id, reason: evaluation.reason });
      return;
    }
    if (request.state !== 'pending') {
      return;
    }
    if (this.now() >= request.expiresAt) {
      request.state = 'failed';
      this.log.warn('wallet response after the attempt expired', { id });
      return;
    }
    request.state = 'settling';
    await this.settle(request, evaluation);
  }

  private async settle(request: BridgeRequest, evaluation: Extract<Evaluation, { kind: 'verified' | 'rejected' }>): Promise<void> {
    const attestation: AttestInput = evaluation.kind === 'verified'
      ? {
          correlationId: request.correlationId,
          result: 1,
          subjectCommitment: subjectCommitment(request.correlationId, request.blindingSecret, evaluation.subjectId),
          presentationHash: evaluation.presentationHash,
        }
      : {
          correlationId: request.correlationId,
          result: 2,
          subjectCommitment: ZERO_HASH,
          presentationHash: evaluation.presentationHash ?? ZERO_HASH,
        };

    let outcome: AttestOutcome;
    try {
      outcome = await this.attestWithRetry(request.id, attestation);
    } catch (error) {
      request.state = 'failed';
      this.log.error('attestation failed', { id: request.id, result: attestation.result, error: (error as Error).message });
      return;
    }

    request.attestation = {
      result: attestation.result,
      subjectCommitment: attestation.subjectCommitment,
      presentationHash: attestation.presentationHash,
      fireflyOperation: outcome.operationId,
      fireflyTransaction: outcome.transactionId,
    };
    if (evaluation.kind === 'verified') {
      request.result = {
        subject_id: evaluation.subjectId,
        issuer: evaluation.issuer,
        presentation_hash: evaluation.presentationHash,
        claims: evaluation.claims,
      };
      request.state = 'verified';
    } else {
      request.state = 'rejected';
    }
    this.log.info('decision attested', {
      id: request.id,
      result: attestation.result,
      reused: outcome.reused,
      operation: outcome.operationId,
      transaction: outcome.transactionId,
      failure: evaluation.kind === 'rejected' ? evaluation.failureType : null,
    });
  }

  private async attestWithRetry(id: string, input: AttestInput): Promise<AttestOutcome> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.firefly.attest(input);
      } catch (error) {
        const delay = this.attestRetryDelaysMs[attempt];
        if (!(error instanceof FireFlyError) || !error.retryable || delay === undefined) {
          throw error;
        }
        this.log.warn('attestation attempt failed, retrying with the same idempotency key', {
          id,
          attempt: attempt + 1,
          error: error.message,
        });
        await this.sleep(delay);
      }
    }
  }
}
