/**
 * The bridge's behaviour, independent of HTTP:
 *
 *  1. WordPress opens a presentation request; the bridge opens a verifier session
 *     for it and hands back the wallet URL. With BRIDGE_DC_API_ORIGINS set it opens
 *     a second, Digital Credentials API session for the same attempt and hands back
 *     its request too; whichever session the holder answers settles the attempt.
 *  2. The verifier rings the bridge's callback for every session update. The
 *     bridge re-reads the session and, once it is SUCCESSFUL or FAILED, computes
 *     the commitments and calls `attest` through FireFly.
 *  3. With a trusted-issuer registry configured (`FIREFLY_REGISTRY_API`), a
 *     SUCCESSFUL session is first checked on chain: `isTrusted(issuer, vct)` for
 *     the presented credential. An untrusted pair is attested as a rejection; a
 *     registry that cannot answer fails the attempt closed, with no attestation.
 *  4. Only after FireFly accepted the attestation does the result become readable,
 *     and it stays readable for the attempt lifetime plus a minute.
 */

import type { Config, DcApiConfig, QueryDefinition } from './config.js';
import { isRecord, isSecureWebUrl } from './config.js';
import { ZERO_HASH, constantTimeEqual, newRequestId, randomToken, subjectCommitment } from './crypto.js';
import type { AttestInput, AttestOutcome, FireFlyClient } from './firefly.js';
import { FireFlyError } from './firefly.js';
import type { Logger } from './log.js';
import type { BridgeRequest, RequestStore } from './store.js';
import { RESULT_GRACE_MS } from './store.js';
import type { DcApiRequest, Evaluation, VerifierClient } from './verifier.js';
import { VerifierError, buildDcApiSessionSetup, buildSessionSetup, evaluateSession } from './verifier.js';

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
  /** Waits between FireFly attempts (the attestation, and the registry query); one more attempt than there are delays. */
  attestRetryDelaysMs?: number[];
  /** Waits between attempts to read a verifier session after a transient failure. */
  sessionReadRetryDelaysMs?: number[];
  sleep?: (ms: number) => Promise<void>;
  /**
   * How long after a presentation request arrived its optional Digital Credentials
   * API session may still be worked on. WordPress waits five seconds for the whole
   * answer (BridgeClient), and the QR code must reach it within that even when the
   * verifier is slow: past this point the extra session is given up, not awaited.
   */
  dcApiDeadlineMs?: number;
}

/** The `dc_api` object of docs/BRIDGE-API.md: what the browser passes to the wallet, and where it posts the answer. */
export interface DcApiOffer {
  requests: DcApiRequest[];
  response_url: string;
}

export interface CreatedRequest {
  id: string;
  wallet_url: string;
  dc_api: DcApiOffer | null;
}

const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const MAX_NONCE_LENGTH = 512;
const MAX_RETURN_URL_LENGTH = 2048;
const DC_API_DEADLINE_MS = 2_000;

export class Bridge {
  private readonly config: Config;
  private readonly store: RequestStore;
  private readonly verifier: VerifierClient;
  private readonly firefly: FireFlyClient;
  private readonly log: Logger;
  private readonly now: () => number;
  private readonly attestRetryDelaysMs: number[];
  private readonly sessionReadRetryDelaysMs: number[];
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly dcApiDeadlineMs: number;
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
    this.sessionReadRetryDelaysMs = options.sessionReadRetryDelaysMs ?? [500, 2_000];
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.dcApiDeadlineMs = options.dcApiDeadlineMs ?? DC_API_DEADLINE_MS;
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
    const returnUrl = parseReturnUrl(body['return_url']);

    if (!this.store.reserveCorrelation(correlationId)) {
      throw new HttpError(409, 'duplicate_correlation_id', 'This correlation_id was already used');
    }

    const id = newRequestId();
    const callbackToken = randomToken();
    const timing = { expiresAt: new Date(expiresAt), retainUntil: new Date(expiresAt + RESULT_GRACE_MS) };
    const setup = buildSessionSetup({
      id,
      query,
      ...timing,
      webhookUrl: `${this.config.callbackUrl}/${id}`,
      webhookToken: callbackToken,
      signedRequest: this.config.verifierSignedRequest,
      ...(returnUrl === undefined ? {} : { returnUrl }),
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

    // The Digital Credentials API session is an extra: the QR code works without it, and
    // must not wait for it. Both of its verifier calls share what is left of the deadline.
    const dcApiDeadline = now + this.dcApiDeadlineMs;
    const dcApiSessionId = this.config.dcApi
      ? await this.openDcApiSession(this.config.dcApi, id, query, queryName, timing, callbackToken, dcApiDeadline)
      : null;

    const request: BridgeRequest = {
      id,
      correlationId,
      nonce,
      blindingSecret,
      query: queryName,
      expiresAt,
      createdAt: now,
      callbackToken,
      dcApi: dcApiSessionId === null ? null : { sessionId: dcApiSessionId },
      state: 'pending',
      recheck: new Set(),
      result: null,
      attestation: null,
    };
    // Stored before the request is read: reading it rings the callback, which must find the request.
    this.store.add(request);
    const dcApi = await this.dcApiOffer(request, dcApiDeadline);
    // The return URL names the login attempt and is not logged, like every other attempt identifier of WordPress's.
    this.log.info('presentation request opened', { id, query: queryName, expiresAt: new Date(expiresAt).toISOString(), dcApi: dcApi !== null, returnUrl: returnUrl !== undefined });
    return { id, wallet_url: created.walletUrl, dc_api: dcApi };
  }

  /**
   * Opens the `dc_api_openid4vp` session of a request: the same query and lifetime,
   * bound to the login pages' origins, ringing the same callback under its own id.
   * A failure, or no time left before `deadline`, is logged and leaves the request
   * with its cross-device session only.
   */
  private async openDcApiSession(
    dcApi: DcApiConfig,
    id: string,
    query: QueryDefinition,
    queryName: string,
    timing: { expiresAt: Date; retainUntil: Date },
    callbackToken: string,
    deadline: number,
  ): Promise<string | null> {
    const left = deadline - this.now();
    if (left <= 0) {
      this.log.warn('no time left to open a Digital Credentials API session, the QR code stands alone', { id, query: queryName });
      return null;
    }
    const sessionId = newRequestId();
    const setup = buildDcApiSessionSetup({
      id: sessionId,
      query,
      ...timing,
      webhookUrl: `${this.config.callbackUrl}/${sessionId}`,
      webhookToken: callbackToken,
      origins: dcApi.origins,
    });
    try {
      const created = await this.verifier.createDcApiSession(setup, left);
      if (created !== sessionId) {
        this.log.error('the verifier ignored the requested Digital Credentials API session id', { id, dcSession: sessionId, query: queryName });
        return null;
      }
      return sessionId;
    } catch (error) {
      this.log.error('could not open a Digital Credentials API session, the QR code stands alone', { id, query: queryName, error: (error as Error).message });
      return null;
    }
  }

  /**
   * The browser's half of the Digital Credentials API session, or null when the
   * request has none, or its request could not be read before `deadline`.
   */
  private async dcApiOffer(request: BridgeRequest, deadline: number): Promise<DcApiOffer | null> {
    if (!request.dcApi || !this.config.dcApi) {
      return null;
    }
    const sessionId = request.dcApi.sessionId;
    const left = deadline - this.now();
    if (left <= 0) {
      // Nobody will ever answer that session: forget it, so a callback for it cannot touch the request.
      this.store.dropDcApiSession(request);
      this.log.warn('no time left to read the Digital Credentials API request, the QR code stands alone', { id: request.id, dcSession: sessionId });
      return null;
    }
    try {
      const requests = await this.verifier.getDcApiRequests(sessionId, left);
      return {
        requests,
        response_url: `${this.config.dcApi.verifierPublicUrl}/verification-session/${encodeURIComponent(sessionId)}/response`,
      };
    } catch (error) {
      this.store.dropDcApiSession(request);
      this.log.error('could not read the Digital Credentials API request, the QR code stands alone', { id: request.id, dcSession: sessionId, error: (error as Error).message });
      return null;
    }
  }

  /**
   * POST /v1/verifier-callbacks/{session}: the verifier's doorbell, for either session
   * of a request. Authenticated by the per-request bearer token the bridge gave the
   * verifier; the body is ignored.
   */
  handleCallback(sessionId: string, authorization: string | undefined): 'accepted' | 'unauthorized' | 'unknown' {
    const request = this.store.findBySession(sessionId);
    if (!request) {
      return 'unknown';
    }
    if (authorization === undefined || !constantTimeEqual(authorization, `Bearer ${request.callbackToken}`)) {
      this.log.warn('callback with a bad token', { id: request.id, session: sessionId });
      return 'unauthorized';
    }
    this.scheduleCheck(sessionId);
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

  /** Deletes expired requests, and retries callbacks the verifier could not be asked about. */
  sweep(): number {
    const removed = this.store.sweep();
    if (removed > 0) {
      this.log.debug('expired requests deleted', { count: removed });
    }
    for (const request of this.store.needingRecheck()) {
      const sessions = [...request.recheck];
      request.recheck.clear();
      for (const sessionId of sessions) {
        this.scheduleCheck(sessionId);
      }
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

  /** One check runs per verifier session at a time; a doorbell during a check queues one more. */
  private scheduleCheck(sessionId: string): void {
    const running = this.checks.get(sessionId);
    if (running) {
      running.again = true;
      return;
    }
    const entry = { again: false };
    this.checks.set(sessionId, entry);
    void (async () => {
      try {
        do {
          entry.again = false;
          try {
            await this.check(sessionId);
          } catch (error) {
            this.log.error('processing a verifier callback crashed', { session: sessionId, error: (error as Error).message });
          }
        } while (entry.again);
      } finally {
        this.checks.delete(sessionId);
        if (this.checks.size === 0) {
          const waiters = this.idleWaiters;
          this.idleWaiters = [];
          waiters.forEach((resolve) => resolve());
        }
      }
    })();
  }

  /**
   * Reads one verifier session of a request and settles the request on a decision.
   * Every state change comes after an await, and the request's other session may
   * have settled it meanwhile, so each one is a compare-and-set on `pending`.
   */
  private async check(sessionId: string): Promise<void> {
    const request = this.store.findBySession(sessionId);
    if (!request || request.state !== 'pending') {
      return;
    }
    const id = request.id;
    const fields = sessionId === id ? { id } : { id, session: sessionId };
    let session;
    try {
      session = await this.readSessionWithRetry(sessionId);
    } catch (error) {
      if (request.state !== 'pending') {
        return;
      }
      if (error instanceof VerifierError && error.status === 404) {
        // The verifier no longer has the session: nothing can settle this attempt.
        request.state = 'failed';
        this.log.error('the verifier no longer has the session', fields);
        return;
      }
      request.recheck.add(sessionId);
      this.log.warn('could not read the verifier session, will try again on the next sweep', { ...fields, error: (error as Error).message });
      return;
    }
    if (request.state !== 'pending') {
      return;
    }
    request.recheck.delete(sessionId);
    const evaluation = evaluateSession(session, this.config.queries[request.query]!);
    if (evaluation.kind === 'undecided') {
      this.log.debug('verifier session still undecided', { ...fields, status: evaluation.status });
      return;
    }
    if (evaluation.kind === 'inconsistent') {
      request.state = 'failed';
      this.log.error('verifier session cannot be used', { ...fields, reason: evaluation.reason });
      return;
    }
    if (this.now() >= request.expiresAt) {
      request.state = 'failed';
      this.log.warn('wallet response after the attempt expired', fields);
      return;
    }
    request.state = 'settling';
    await this.settle(request, evaluation, sessionId !== id);
  }

  private async settle(request: BridgeRequest, verdict: Extract<Evaluation, { kind: 'verified' | 'rejected' }>, viaDcApi: boolean): Promise<void> {
    let evaluation = verdict;
    if (evaluation.kind === 'verified' && this.config.firefly.registryApiName !== undefined) {
      const trusted = await this.registryTrusts(request.id, evaluation.issuer, evaluation.vct);
      if (trusted === null) {
        // Fail closed: no decision was reached, so nothing is attested and the attempt fails.
        request.state = 'failed';
        return;
      }
      if (!trusted) {
        evaluation = { kind: 'rejected', presentationHash: evaluation.presentationHash, failureType: 'untrusted_issuer' };
      }
    }

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
      outcome = await this.fireflyWithRetry(request.id, 'attestation', () => this.firefly.attest(attestation));
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
      dcApi: viaDcApi,
      reused: outcome.reused,
      operation: outcome.operationId,
      transaction: outcome.transactionId,
      failure: evaluation.kind === 'rejected' ? evaluation.failureType : null,
    });
  }

  private async readSessionWithRetry(sessionId: string): Promise<Record<string, unknown>> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.verifier.getSession(sessionId);
      } catch (error) {
        const delay = this.sessionReadRetryDelaysMs[attempt];
        if (!(error instanceof VerifierError) || !error.retryable || delay === undefined) {
          throw error;
        }
        this.log.debug('verifier session read failed, retrying', { session: sessionId, attempt: attempt + 1, error: error.message });
        await this.sleep(delay);
      }
    }
  }

  /**
   * The on-chain trust decision for the presented credential: true or false as the
   * registry answers, or null when no answer could be had (FireFly down, the API
   * missing, an unusable output), which the caller fails closed on. A credential
   * that names no issuer or no type cannot be in the registry, so it is untrusted
   * without a query. Neither value is logged: the issuer and the vct name the
   * credential, and the log holds identifiers and outcomes only.
   */
  private async registryTrusts(id: string, issuer: string | null, vct: string | null): Promise<boolean | null> {
    if (issuer === null || vct === null) {
      this.log.warn('presented credential names no issuer or no vct, so the registry cannot trust it', { id });
      return false;
    }
    let trusted: boolean;
    try {
      trusted = await this.fireflyWithRetry(id, 'registry query', () => this.firefly.isTrusted(issuer, vct));
    } catch (error) {
      this.log.error('the trusted-issuer registry could not be asked, the attempt fails closed', { id, error: (error as Error).message });
      return null;
    }
    this.log.debug('trusted-issuer registry answered', { id, trusted });
    return trusted;
  }

  /** Repeats a FireFly call while it fails for a transient reason; the attestation is safe to repeat by its idempotency key, the query because it writes nothing. */
  private async fireflyWithRetry<T>(id: string, what: 'attestation' | 'registry query', call: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await call();
      } catch (error) {
        const delay = this.attestRetryDelaysMs[attempt];
        if (!(error instanceof FireFlyError) || !error.retryable || delay === undefined) {
          throw error;
        }
        this.log.warn(`${what} attempt failed, retrying`, { id, attempt: attempt + 1, error: error.message });
        await this.sleep(delay);
      }
    }
  }
}

/**
 * `return_url` of docs/BRIDGE-API.md: where a wallet on the holder's own device sends
 * the holder once it has presented, or undefined when WordPress named none. The
 * verifier hands it to the wallet as `redirect_uri` and the wallet opens it in the
 * browser, so only an absolute web address is accepted: https, or plain http on
 * localhost for a test stack (the rule of BRIDGE_DC_API_ORIGINS), without credentials.
 * The URL is WordPress's own login or profile page naming the attempt; it binds
 * nothing, WordPress's cookie binding does (docs/SECURITY-MODEL.md, threat 24).
 */
function parseReturnUrl(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  const refused = new HttpError(400, 'invalid_request', 'return_url must be an absolute https URL without credentials (plain http on localhost only)');
  if (typeof value !== 'string' || value === '' || value.length > MAX_RETURN_URL_LENGTH) {
    throw refused;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw refused;
  }
  if (!isSecureWebUrl(url) || url.username !== '' || url.password !== '') {
    throw refused;
  }
  return url.href;
}
