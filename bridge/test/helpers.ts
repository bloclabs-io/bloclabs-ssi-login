/**
 * Test doubles: a walt.id verifier-api2 look-alike, a FireFly look-alike, and a
 * bridge listening on a random port with a fake clock and captured logs.
 */

import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import { Bridge } from '../src/bridge.js';
import { loadConfig, type Config } from '../src/config.js';
import { FireFlyClient } from '../src/firefly.js';
import { createLogger } from '../src/log.js';
import { createServer as createBridgeServer } from '../src/server.js';
import { RequestStore } from '../src/store.js';
import { VerifierClient } from '../src/verifier.js';

export const AUTH_TOKEN = 'test-bridge-token-0123456789abcdef0123456789abcdef';
export const SIGNING_KEY = '0x1111111111111111111111111111111111111111';
export const BLINDING_SECRET = 'b1'.repeat(32);
export const ISSUER = 'did:web:issuer.example.com';
export const VCT = 'https://issuer.example.com/credentials/login';

/** RFC 7517 appendix A.1 EC public key. */
export const HOLDER_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
  y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
};

export const SD_JWT_PRESENTATION =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSJ9.c2lnbmF0dXJl'
  + '~WyJzYWx0MSIsImdpdmVuX25hbWUiLCJBZGEiXQ~WyJzYWx0MiIsImVtYWlsIiwiYWRhQGV4YW1wbGUuY29tIl0'
  + '~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6InZlcmlmaWVyLW5vbmNlIn0.a2Itc2lnbmF0dXJl';

/**
 * sha256 of the RFC 8785 canonical JSON of {login: [SD_JWT_PRESENTATION]}, computed outside
 * the bridge. It pins the presentation_hash definition of docs/BRIDGE-API.md: a change in how
 * the vp_token is read or serialised fails a test instead of silently changing the hashes on chain.
 */
export const PRESENTATION_HASH_VECTOR = '59469797ce54d2b524ec659e4ad6ca0c759687de5b92a4c863fc15084aa8a15a';

export const QUERIES = {
  default: {
    dcql_query: {
      credentials: [
        {
          id: 'login',
          format: 'dc+sd-jwt',
          meta: { vct_values: [VCT] },
          claims: [{ path: ['given_name'] }, { path: ['email'] }, { path: ['address', 'locality'] }],
        },
      ],
    },
    policies: { vc_policies: ['signature', 'expiration', 'not-before'] },
  },
  all: {
    dcql_query: {
      credentials: [{ id: 'any', format: 'dc+sd-jwt', meta: { vct_values: [VCT] } }],
    },
  },
};

export function baseEnv(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    BRIDGE_AUTH_TOKEN: AUTH_TOKEN,
    BRIDGE_CALLBACK_URL: 'http://127.0.0.1:1/v1/verifier-callbacks',
    VERIFIER_URL: 'http://127.0.0.1:1',
    FIREFLY_URL: 'http://127.0.0.1:1',
    FIREFLY_SIGNING_KEY: SIGNING_KEY,
    BRIDGE_QUERIES: JSON.stringify(QUERIES),
    ...overrides,
  };
}

export function credentialData(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    vct: VCT,
    iat: 1_762_000_000,
    exp: 1_793_536_000,
    cnf: { jwk: HOLDER_JWK },
    _sd_alg: 'sha-256',
    given_name: 'Ada',
    family_name: 'Lovelace',
    email: 'ada@example.com',
    address: { locality: 'London', street_address: '12 St James Square' },
    ...overrides,
  };
}

export interface SessionOptions {
  queryId?: string;
  vpToken?: Record<string, string[]>;
  credential?: Record<string, unknown> | null;
  credentialData?: Record<string, unknown>;
}

/** A session as GET /verification-session/{id}/info reports it after a successful presentation. */
export function successfulSession(id: string, options: SessionOptions = {}): Record<string, unknown> {
  const queryId = options.queryId ?? 'login';
  const vpToken = options.vpToken ?? { [queryId]: [SD_JWT_PRESENTATION] };
  const credential = options.credential === null
    ? null
    : options.credential ?? {
        type: 'vc-sd_jwt',
        dmtype: 'sdjwtvc',
        format: 'dc+sd-jwt',
        credentialData: options.credentialData ?? credentialData(),
        issuer: ISSUER,
        subject: null,
        signed: 'eyJhbGciOiJFUzI1NiJ9.e30.c2ln',
        signature: { type: 'sd-jwt' },
      };
  return {
    id,
    status: 'SUCCESSFUL',
    attempted: true,
    creationDate: '2026-11-03T10:00:00Z',
    authorizationRequest: { response_type: 'vp_token', client_id: 'redirect_uri:https://verifier.example.com/r', nonce: 'verifier-nonce', state: 'verifier-state' },
    presented_raw_data: { vpToken, state: 'verifier-state' },
    presented_credentials: credential === null ? {} : { [queryId]: [credential] },
    policy_results: { vp_policies: {}, vc_policies: [], specific_vc_policies: {} },
  };
}

export function failedSession(id: string, withPresentation = true): Record<string, unknown> {
  return {
    id,
    status: 'FAILED',
    attempted: true,
    authorizationRequest: { nonce: 'verifier-nonce', state: 'verifier-state' },
    ...(withPresentation ? { presented_raw_data: { vpToken: { login: [SD_JWT_PRESENTATION] }, state: 'verifier-state' } } : {}),
    statusReason: 'Presentation validation failed',
    failure: {
      type: 'presentation_validation',
      reason: 'Presentation validation failed: Expected verifier-nonce, got other',
      failed_policies: { login: { 'nonce-check': { success: false, errors: ['nonce mismatch'] } } },
    },
  };
}

interface StoredSession {
  setup: Record<string, unknown>;
  session: Record<string, unknown>;
}

export interface MockVerifier {
  url: string;
  createCalls: Array<Record<string, unknown>>;
  infoCalls: string[];
  sessions: Map<string, StoredSession>;
  /** When set, the next create answers this status with a walt.id style error body. */
  failNextCreate: number | null;
  /** How many of the next session reads answer 503. */
  failNextInfo: number;
  setSession(id: string, session: Record<string, unknown>): void;
  /** Posts a session update to the webhook configured for the session, as walt.id does. */
  fireCallback(id: string, event?: string, token?: string): Promise<number>;
  close(): Promise<void>;
}

export async function startMockVerifier(): Promise<MockVerifier> {
  const sessions = new Map<string, StoredSession>();
  const createCalls: Array<Record<string, unknown>> = [];
  const infoCalls: string[] = [];
  const state = { failNextCreate: null as number | null, failNextInfo: 0 };

  const server = createServer(async (req, res) => {
    const path = req.url ?? '';
    if (req.method === 'POST' && path === '/verification-session/create') {
      const setup = JSON.parse(await readBody(req)) as Record<string, unknown>;
      createCalls.push(setup);
      if (state.failNextCreate !== null) {
        const status = state.failNextCreate;
        state.failNextCreate = null;
        json(res, status, { exception: true, status: 'Bad Request', message: `simulated failure ${JSON.stringify(setup)}` });
        return;
      }
      const core = setup['core_flow'] as Record<string, unknown>;
      const id = typeof core['sessionId'] === 'string' ? core['sessionId'] : randomUUID();
      sessions.set(id, {
        setup,
        session: {
          id,
          status: 'UNUSED',
          attempted: false,
          authorizationRequest: { nonce: 'verifier-nonce', state: 'verifier-state' },
        },
      });
      json(res, 200, {
        sessionId: id,
        bootstrapAuthorizationRequestUrl: `openid4vp://authorize?client_id=redirect_uri%3A${encodeURIComponent(`${url()}/verification-session/${id}/response`)}&request_uri=${encodeURIComponent(`${url()}/verification-session/${id}/request`)}`,
        fullAuthorizationRequestUrl: `openid4vp://authorize?client_id=x&dcql_query=%7B%7D&nonce=verifier-nonce`,
        creationTarget: null,
        data: null,
      });
      return;
    }
    const info = /^\/verification-session\/([^/]+)\/info$/.exec(path);
    if (req.method === 'GET' && info) {
      const id = decodeURIComponent(info[1]!);
      infoCalls.push(id);
      if (state.failNextInfo > 0) {
        state.failNextInfo--;
        json(res, 503, { exception: true, status: 'Service Unavailable', message: 'simulated outage' });
        return;
      }
      const stored = sessions.get(id);
      if (!stored) {
        json(res, 404, { exception: true, status: 'Not Found', message: `Verification session not found: ${id}` });
        return;
      }
      json(res, 200, stored.session);
      return;
    }
    json(res, 404, { exception: true, message: 'no such route' });
  });
  await listen(server);
  const url = () => `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    url: url(),
    createCalls,
    infoCalls,
    sessions,
    get failNextCreate() {
      return state.failNextCreate;
    },
    set failNextCreate(value: number | null) {
      state.failNextCreate = value;
    },
    get failNextInfo() {
      return state.failNextInfo;
    },
    set failNextInfo(value: number) {
      state.failNextInfo = value;
    },
    setSession(id, session) {
      const stored = sessions.get(id);
      if (!stored) {
        throw new Error(`no session ${id}`);
      }
      stored.session = session;
    },
    async fireCallback(id, event = 'credential_policy_results_available', token) {
      const stored = sessions.get(id);
      if (!stored) {
        throw new Error(`no session ${id}`);
      }
      const core = stored.setup['core_flow'] as Record<string, unknown>;
      const webhook = (core['notifications'] as { webhook: { url: string; bearer_token: string } }).webhook;
      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token ?? webhook.bearer_token}` },
        body: JSON.stringify({ target: id, event, session: stored.session }),
      });
      await response.text();
      return response.status;
    },
    close: () => closeServer(server),
  };
}

export interface FireFlyCall {
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: Record<string, unknown>;
}

export interface ScriptedAnswer {
  status: number;
  body: unknown;
  /** Send the headers and the first bytes of the body, then drop the connection. */
  truncate?: boolean;
}

export type ScriptedResponse = (call: FireFlyCall) => Promise<ScriptedAnswer> | ScriptedAnswer;

export interface MockFireFly {
  url: string;
  invokes: FireFlyCall[];
  statusCalls: string[];
  /** Consumed one per invoke; when empty the invoke succeeds with a confirmed operation. */
  responses: ScriptedResponse[];
  transactionStatus: Map<string, string>;
  /** Every `query/isTrusted` call on a trusted-issuer registry API. */
  queries: FireFlyCall[];
  /** Consumed one per registry query; when empty the registry answers from `trusted`. */
  queryResponses: ScriptedResponse[];
  /** Issuer and vct pairs the registry trusts, as `registryKey()` makes them. */
  trusted: Set<string>;
  close(): Promise<void>;
}

/** The TrustedIssuerRegistry key of a pair, for `MockFireFly.trusted`. */
export function registryKey(issuer: unknown, vct: unknown): string {
  return `${String(issuer)}\n${String(vct)}`;
}

export function okOperation(): ScriptedAnswer {
  return { status: 200, body: { id: randomUUID(), tx: randomUUID(), type: 'blockchain_invoke', status: 'Succeeded', output: {} } };
}

export function duplicateKey(transactionId: string): ScriptedAnswer {
  return { status: 409, body: { error: `FF10431: Idempotency key 'bloclabs-ssi-login:x' already used for transaction '${transactionId}'` } };
}

export async function startMockFireFly(): Promise<MockFireFly> {
  const invokes: FireFlyCall[] = [];
  const statusCalls: string[] = [];
  const responses: ScriptedResponse[] = [];
  const transactionStatus = new Map<string, string>();
  const queries: FireFlyCall[] = [];
  const queryResponses: ScriptedResponse[] = [];
  const trusted = new Set<string>();

  const server = createServer(async (req, res) => {
    const path = req.url ?? '';
    if (req.method === 'POST' && /\/query\/isTrusted$/.test(path)) {
      const call: FireFlyCall = { path, headers: req.headers, body: JSON.parse(await readBody(req)) as Record<string, unknown> };
      queries.push(call);
      const scripted = queryResponses.shift();
      if (scripted) {
        const answer = await scripted(call);
        json(res, answer.status, answer.body);
        return;
      }
      const input = (call.body['input'] ?? {}) as Record<string, unknown>;
      json(res, 200, { output: trusted.has(registryKey(input['issuer'], input['vct'])) });
      return;
    }
    if (req.method === 'POST' && /\/invoke\//.test(path)) {
      const call: FireFlyCall = { path, headers: req.headers, body: JSON.parse(await readBody(req)) as Record<string, unknown> };
      invokes.push(call);
      const scripted = responses.shift();
      const answer = scripted ? await scripted(call) : okOperation();
      if (answer.truncate) {
        const payload = JSON.stringify(answer.body);
        res.writeHead(answer.status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
        res.write(payload.slice(0, 8));
        res.destroy();
        return;
      }
      json(res, answer.status, answer.body);
      return;
    }
    const status = /\/transactions\/([^/]+)\/status$/.exec(path);
    if (req.method === 'GET' && status) {
      const id = decodeURIComponent(status[1]!);
      statusCalls.push(id);
      json(res, 200, { status: transactionStatus.get(id) ?? 'Succeeded', details: [] });
      return;
    }
    json(res, 404, { error: 'FF10109: Not found' });
  });
  await listen(server);

  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    invokes,
    statusCalls,
    responses,
    transactionStatus,
    queries,
    queryResponses,
    trusted,
    close: () => closeServer(server),
  };
}

export interface TestBridge {
  url: string;
  bridge: Bridge;
  config: Config;
  logs: string[];
  clock: { now: number };
  verifier: MockVerifier;
  firefly: MockFireFly;
  /** Authenticated call to the bridge as WordPress. */
  call(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<{ status: number; body: unknown; headers: Headers }>;
  close(): Promise<void>;
}

export async function startBridge(envOverrides: Record<string, string | undefined> = {}): Promise<TestBridge> {
  const verifier = await startMockVerifier();
  const firefly = await startMockFireFly();
  const clock = { now: Date.parse('2026-11-03T12:00:00Z') };
  const logs: string[] = [];

  const config = loadConfig(baseEnv({ VERIFIER_URL: verifier.url, FIREFLY_URL: firefly.url, ...envOverrides }));
  const log = createLogger('debug', (line) => logs.push(line));
  const bridge = new Bridge({
    config,
    store: new RequestStore(() => clock.now),
    verifier: new VerifierClient(config.verifierUrl),
    firefly: new FireFlyClient(config.firefly, fetch, 2_000, 2_000),
    log,
    now: () => clock.now,
    attestRetryDelaysMs: [5, 5],
    sessionReadRetryDelaysMs: [5, 5],
  });
  const server = createBridgeServer(bridge, config, log);
  await listen(server);
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  config.callbackUrl = `${url}/v1/verifier-callbacks`;

  return {
    url,
    bridge,
    config,
    logs,
    clock,
    verifier,
    firefly,
    async call(method, path, body, headers = {}) {
      const response = await fetch(url + path, {
        method,
        headers: { Authorization: `Bearer ${AUTH_TOKEN}`, 'Content-Type': 'application/json', ...headers },
        body: body === undefined ? null : typeof body === 'string' ? body : JSON.stringify(body),
      });
      const text = await response.text();
      let parsed: unknown = text;
      try {
        parsed = JSON.parse(text);
      } catch {
        // keep the text
      }
      return { status: response.status, body: parsed, headers: response.headers };
    },
    async close() {
      await bridge.idle();
      await closeServer(server);
      await verifier.close();
      await firefly.close();
    },
  };
}

export function requestBody(overrides: Record<string, unknown> = {}, clockNow = Date.parse('2026-11-03T12:00:00Z')): Record<string, unknown> {
  return {
    correlation_id: '3575e334c14dcc31670ded8ad7c600007ccd69a694c8251151b51c8780b97fea',
    nonce: 'wp-nonce-q2F8kZ0',
    blinding_secret: BLINDING_SECRET,
    query: 'default',
    expires_at: new Date(clockNow + 180_000).toISOString(),
    ...overrides,
  };
}

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

function listen(server: Server): Promise<void> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
    server.closeAllConnections();
  });
}
