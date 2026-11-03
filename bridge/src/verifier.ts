/**
 * walt.id verifier-api2 client, and the reading of a finished session.
 *
 * Endpoints (waltid-services/waltid-verifier-api2, checked against v1.2.0 and main):
 *   POST /verification-session/create          VerificationSessionSetup -> {sessionId, bootstrapAuthorizationRequestUrl, ...}
 *   GET  /verification-session/{id}/info       Verification2Session (public view)
 * Session updates are posted to `core_flow.notifications.webhook.url` as
 * {target, event, session}; the bridge treats them as a doorbell and re-reads
 * the session, it never trusts the posted body.
 */

import type { DcqlClaimsQuery, DcqlCredentialQuery, QueryDefinition } from './config.js';
import { isRecord } from './config.js';
import { jwkThumbprintUri, presentationHash } from './crypto.js';

export class VerifierError extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
    readonly status: number | null = null,
  ) {
    super(message);
  }
}

export interface SessionSetupOptions {
  id: string;
  query: QueryDefinition;
  expiresAt: Date;
  retainUntil: Date;
  webhookUrl: string;
  webhookToken: string;
}

/**
 * The cross-device (QR code) flow. The verifier picks the OpenID4VP nonce and
 * state itself; WordPress's nonce is not used, docs/BRIDGE-API.md allows that.
 */
export function buildSessionSetup(options: SessionSetupOptions): Record<string, unknown> {
  const core: Record<string, unknown> = {
    sessionId: options.id,
    dcql_query: options.query.dcql_query,
    expiration_date: options.expiresAt.toISOString(),
    retention_date: options.retainUntil.toISOString(),
    notifications: { webhook: { url: options.webhookUrl, bearer_token: options.webhookToken } },
  };
  if (options.query.policies) {
    core['policies'] = options.query.policies;
  }
  return { flow_type: 'cross_device', core_flow: core };
}

export interface CreatedSession {
  sessionId: string;
  walletUrl: string;
}

const MAX_SESSION_BYTES = 16 * 1024 * 1024;

export class VerifierClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs = 5_000,
  ) {}

  async createSession(setup: Record<string, unknown>): Promise<CreatedSession> {
    const body = await this.call('POST', '/verification-session/create', setup);
    const sessionId = body['sessionId'];
    const walletUrl = body['bootstrapAuthorizationRequestUrl'] ?? body['fullAuthorizationRequestUrl'];
    if (typeof sessionId !== 'string' || sessionId === '' || typeof walletUrl !== 'string' || walletUrl === '') {
      throw new VerifierError('The verifier answered without a session id or an authorization request URL', false);
    }
    return { sessionId, walletUrl };
  }

  async getSession(id: string): Promise<Record<string, unknown>> {
    return this.call('GET', `/verification-session/${encodeURIComponent(id)}/info`);
  }

  private async call(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    let response: Response;
    try {
      response = await this.fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? null : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new VerifierError(`The verifier is unreachable: ${(error as Error).message}`, true);
    }
    const length = Number(response.headers.get('content-length') ?? '0');
    if (length > MAX_SESSION_BYTES) {
      throw new VerifierError('The verifier answered with a body larger than the bridge accepts', false, response.status);
    }
    const text = await response.text();
    if (!response.ok) {
      throw new VerifierError(
        `The verifier answered HTTP ${response.status}: ${text.slice(0, 500)}`,
        response.status >= 500,
        response.status,
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new VerifierError('The verifier answered with invalid JSON', false, response.status);
    }
    if (!isRecord(parsed)) {
      throw new VerifierError('The verifier answered with something other than a JSON object', false, response.status);
    }
    return parsed;
  }
}

export type Evaluation =
  | { kind: 'undecided'; status: string }
  | { kind: 'verified'; subjectId: string; issuer: string | null; claims: Record<string, unknown>; presentationHash: string }
  | { kind: 'rejected'; presentationHash: string | null; failureType: string | null }
  /** A successful session the bridge cannot turn into a subject: never attested, logged as an error. */
  | { kind: 'inconsistent'; reason: string };

/**
 * Reads a session as the verifier reports it. Only `SUCCESSFUL` and `FAILED`
 * are decisions; everything else is still in flight.
 */
export function evaluateSession(session: Record<string, unknown>, query: QueryDefinition): Evaluation {
  const status = typeof session['status'] === 'string' ? session['status'] : 'UNKNOWN';
  const vpToken = rawVpToken(session);

  if (status === 'FAILED') {
    const failure = session['failure'];
    return {
      kind: 'rejected',
      presentationHash: vpToken ? presentationHash(vpToken) : null,
      failureType: isRecord(failure) && typeof failure['type'] === 'string' ? failure['type'] : null,
    };
  }
  if (status !== 'SUCCESSFUL') {
    return { kind: 'undecided', status };
  }
  if (!vpToken) {
    return { kind: 'inconsistent', reason: 'successful session without presented_raw_data.vpToken' };
  }

  const presented = session['presented_credentials'];
  if (!isRecord(presented)) {
    return { kind: 'inconsistent', reason: 'successful session without presented_credentials' };
  }
  let credentialQuery: DcqlCredentialQuery | undefined;
  let credential: Record<string, unknown> | undefined;
  for (const candidate of query.dcql_query.credentials) {
    const list = presented[candidate.id];
    if (Array.isArray(list) && list.length > 0 && isRecord(list[0])) {
      credentialQuery = candidate;
      credential = list[0];
      break;
    }
  }
  if (!credentialQuery || !credential) {
    return { kind: 'inconsistent', reason: 'no presented credential matches a configured credential query' };
  }
  if (credential['format'] !== 'dc+sd-jwt' && credential['type'] !== 'vc-sd_jwt') {
    return { kind: 'inconsistent', reason: 'presented credential is not an SD-JWT VC' };
  }
  const data = credential['credentialData'];
  if (!isRecord(data)) {
    return { kind: 'inconsistent', reason: 'presented credential has no credentialData' };
  }

  const subjectId = holderSubjectId(data['cnf']);
  if (subjectId === null) {
    return { kind: 'inconsistent', reason: 'presented credential has no usable cnf (holder key)' };
  }

  const issuer = typeof credential['issuer'] === 'string' && credential['issuer'] !== ''
    ? credential['issuer']
    : typeof data['iss'] === 'string' ? data['iss'] : null;

  return {
    kind: 'verified',
    subjectId,
    issuer,
    claims: selectClaims(data, credentialQuery.claims),
    presentationHash: presentationHash(vpToken),
  };
}

function rawVpToken(session: Record<string, unknown>): Record<string, string[]> | undefined {
  const raw = session['presented_raw_data'];
  if (!isRecord(raw) || !isRecord(raw['vpToken'])) {
    return undefined;
  }
  const vpToken: Record<string, string[]> = {};
  for (const [queryId, presentations] of Object.entries(raw['vpToken'])) {
    if (!Array.isArray(presentations) || !presentations.every((item) => typeof item === 'string')) {
      return undefined;
    }
    vpToken[queryId] = presentations as string[];
  }
  return vpToken;
}

/**
 * The stable holder identifier: the RFC 9278 thumbprint URI of `cnf.jwk`, or the
 * DID behind `cnf.kid`. walt.id accepts no other `cnf` method for key binding.
 */
export function holderSubjectId(cnf: unknown): string | null {
  if (!isRecord(cnf)) {
    return null;
  }
  if (isRecord(cnf['jwk'])) {
    try {
      return jwkThumbprintUri(cnf['jwk']);
    } catch {
      return null;
    }
  }
  const kid = cnf['kid'];
  if (typeof kid === 'string' && kid.startsWith('did:')) {
    const did = kid.split('#', 1)[0] ?? '';
    return did.length > 4 ? did : null;
  }
  return null;
}

/** Registered and structural SD-JWT VC claims, never returned as user claims. */
const STRUCTURAL_CLAIMS = new Set(['iss', 'iat', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'status', '_sd', '_sd_alg', '...']);

/**
 * Only what the query disclosed: the values at the requested DCQL claim paths,
 * or, for a query without `claims`, the credential minus its registered claims.
 */
export function selectClaims(data: Record<string, unknown>, claimsQueries: DcqlClaimsQuery[] | undefined): Record<string, unknown> {
  if (!claimsQueries) {
    return stripStructural(data) as Record<string, unknown>;
  }
  const out: Record<string, unknown> = {};
  for (const claim of claimsQueries) {
    const value = resolveClaimPath(data, claim.path);
    if (value !== undefined) {
      setClaimPath(out, claim.path, value);
    }
  }
  return out;
}

function stripStructural(value: unknown, top = true): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => stripStructural(item, false));
  }
  if (!isRecord(value)) {
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === '_sd' || key === '_sd_alg' || key === '...' || (top && STRUCTURAL_CLAIMS.has(key))) {
      continue;
    }
    out[key] = stripStructural(item, false);
  }
  return out;
}

/** OpenID4VP 1.0 §7 claims path pointer: string = key, integer = index, null = every element. */
export function resolveClaimPath(data: unknown, path: Array<string | number | null>): unknown {
  let current: unknown[] = [data];
  let wildcard = false;
  for (const segment of path) {
    const next: unknown[] = [];
    for (const value of current) {
      if (segment === null) {
        if (Array.isArray(value)) {
          wildcard = true;
          next.push(...value);
        }
      } else if (typeof segment === 'string') {
        if (isRecord(value) && segment in value) {
          next.push(value[segment]);
        }
      } else if (Array.isArray(value) && segment < value.length) {
        next.push(value[segment]);
      }
    }
    current = next;
  }
  if (current.length === 0) {
    return undefined;
  }
  return wildcard ? current : current[0];
}

function setClaimPath(target: Record<string, unknown>, path: Array<string | number | null>, value: unknown): void {
  let cursor = target;
  for (let index = 0; index < path.length; index++) {
    const segment = path[index];
    const last = index === path.length - 1;
    if (typeof segment !== 'string') {
      // An array index or wildcard: keep the resolved value at this point of the path.
      return;
    }
    if (last) {
      cursor[segment] = value;
      return;
    }
    const nextSegment = path[index + 1];
    if (typeof nextSegment !== 'string') {
      cursor[segment] = value;
      return;
    }
    const existing = cursor[segment];
    if (!isRecord(existing)) {
      cursor[segment] = {};
    }
    cursor = cursor[segment] as Record<string, unknown>;
  }
}
