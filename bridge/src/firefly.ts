/**
 * FireFly contract API client: one call per login decision, and, when a
 * trusted-issuer registry is configured, one query before it.
 *
 *   POST /api/v1/namespaces/{ns}/apis/{api}/invoke/attest?confirm=true
 *   {"key": <verifier address>, "input": {...}, "idempotencyKey": "bloclabs-ssi-login:<correlation id>"}
 *
 * The idempotency key is derived from the correlation id, so a retry after a
 * timeout or a crash can never attest the same attempt twice: FireFly answers
 * 409 FF10431 ("Idempotency key ... already used for transaction ...") and the
 * bridge reads that transaction's status instead of sending again.
 * (hyperledger/firefly v1.5.0: internal/contracts/manager.go, coremsgs FF10431.)
 *
 *   POST /api/v1/namespaces/{ns}/apis/{registry}/query/isTrusted
 *   {"input": {"issuer": "...", "vct": "..."}}  ->  {"output": true|false}
 *
 * A view call on the TrustedIssuerRegistry contract: nothing is signed or
 * written, so it can be repeated freely, and any answer other than a boolean
 * is an error for the caller to fail closed on.
 */

import type { FireFlyConfig } from './config.js';
import { isRecord } from './config.js';

export class FireFlyError extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
    readonly status: number | null = null,
  ) {
    super(message);
  }
}

export interface AttestInput {
  /** 64 lowercase hex characters, without 0x. */
  correlationId: string;
  result: 1 | 2;
  subjectCommitment: string;
  presentationHash: string;
}

export interface AttestOutcome {
  operationId: string | null;
  transactionId: string | null;
  /** True when FireFly already held this idempotency key: nothing new was sent. */
  reused: boolean;
}

const IDEMPOTENCY_PREFIX = 'bloclabs-ssi-login:';
const DUPLICATE_KEY_CODE = 'FF10431';

export function idempotencyKey(correlationId: string): string {
  return IDEMPOTENCY_PREFIX + correlationId.toLowerCase();
}

export class FireFlyClient {
  constructor(
    private readonly config: FireFlyConfig,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly invokeTimeoutMs = 30_000,
    private readonly queryTimeoutMs = 5_000,
  ) {}

  async attest(input: AttestInput): Promise<AttestOutcome> {
    const body = {
      key: this.config.signingKey,
      input: {
        correlationId: '0x' + input.correlationId.toLowerCase(),
        result: input.result,
        subjectCommitment: '0x' + input.subjectCommitment.toLowerCase(),
        presentationHash: '0x' + input.presentationHash.toLowerCase(),
      },
      idempotencyKey: idempotencyKey(input.correlationId),
    };
    const path = `apis/${encodeURIComponent(this.config.apiName)}/invoke/attest?confirm=true`;
    const { status, data, text } = await this.request('POST', path, body, this.invokeTimeoutMs);

    if (status >= 200 && status < 300) {
      return {
        operationId: typeof data?.['id'] === 'string' ? data['id'] : null,
        transactionId: typeof data?.['tx'] === 'string' ? data['tx'] : null,
        reused: false,
      };
    }

    const message = typeof data?.['error'] === 'string' ? data['error'] : `HTTP ${status} ${text.slice(0, 200)}`;
    if (status === 409 && message.includes(DUPLICATE_KEY_CODE)) {
      const transactionId = /transaction '([0-9a-fA-F-]+)'/.exec(message)?.[1] ?? null;
      if (transactionId !== null) {
        const txStatus = await this.transactionStatus(transactionId);
        if (txStatus === 'Failed') {
          throw new FireFlyError(`FireFly transaction ${transactionId} for this attempt failed earlier`, false, status);
        }
      }
      return { operationId: null, transactionId, reused: true };
    }
    throw new FireFlyError(`FireFly refused the attestation: ${message}`, status >= 500, status);
  }

  /**
   * `TrustedIssuerRegistry.isTrusted(issuer, vct)` through the registry's contract API
   * (`FIREFLY_REGISTRY_API`). Resolves to the contract's answer, and to nothing else:
   * an unreachable FireFly, an unknown API, or an output that is not a boolean is a
   * FireFlyError, so that the caller never mistakes a missing answer for a decision.
   */
  async isTrusted(issuer: string, vct: string): Promise<boolean> {
    const registry = this.config.registryApiName;
    if (registry === undefined) {
      throw new FireFlyError('No trusted-issuer registry is configured (FIREFLY_REGISTRY_API)', false);
    }
    const path = `apis/${encodeURIComponent(registry)}/query/isTrusted`;
    const { status, data, text } = await this.request('POST', path, { input: { issuer, vct } }, this.queryTimeoutMs);

    if (status >= 200 && status < 300) {
      const output = data?.['output'];
      if (output === true || output === false) {
        return output;
      }
      throw new FireFlyError('The trusted-issuer registry answered without a boolean output', false, status);
    }
    const message = typeof data?.['error'] === 'string' ? data['error'] : `HTTP ${status} ${text.slice(0, 200)}`;
    throw new FireFlyError(`The trusted-issuer registry could not be queried: ${message}`, status >= 500, status);
  }

  /** `Succeeded`, `Pending` or `Failed` (FireFly TransactionStatus.status). */
  async transactionStatus(transactionId: string): Promise<string> {
    const { status, data, text } = await this.request(
      'GET',
      `transactions/${encodeURIComponent(transactionId)}/status`,
      undefined,
      this.queryTimeoutMs,
    );
    if (status < 200 || status >= 300 || typeof data?.['status'] !== 'string') {
      throw new FireFlyError(`FireFly could not report transaction ${transactionId}: HTTP ${status} ${text.slice(0, 200)}`, true, status);
    }
    return data['status'];
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    body: Record<string, unknown> | undefined,
    timeoutMs: number,
  ): Promise<{ status: number; data: Record<string, unknown> | null; text: string }> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (this.config.authHeader) {
      headers['Authorization'] = this.config.authHeader;
    }
    const url = `${this.config.url}/api/v1/namespaces/${encodeURIComponent(this.config.namespace)}/${path}`;
    let response: Response;
    let text: string;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      // Reading the body is part of the transport: a reset or a timeout here is retried
      // with the same idempotency key, like a failure to connect.
      text = await response.text();
    } catch (error) {
      throw new FireFlyError(`FireFly is unreachable: ${(error as Error).message}`, true);
    }
    let data: Record<string, unknown> | null = null;
    try {
      const parsed: unknown = JSON.parse(text);
      data = isRecord(parsed) ? parsed : null;
    } catch {
      data = null;
    }
    return { status: response.status, data, text };
  }
}
