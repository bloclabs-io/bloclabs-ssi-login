/**
 * Configuration, from environment variables only.
 *
 * Every value is read once at start-up. Anything the bridge cannot run safely
 * without (the WordPress auth token, the FireFly signing key, a `default`
 * query) is a start-up error, not a runtime surprise.
 */

import type { LogLevel } from './log.js';
import { isLogLevel } from './log.js';

export class ConfigError extends Error {}

/** A named credential query: what is passed to the verifier, verbatim, plus what the bridge needs from it. */
export interface QueryDefinition {
  /** The OpenID4VP 1.0 DCQL query the verifier sends to the wallet. */
  dcql_query: DcqlQuery;
  /** walt.id verification policies (`vp_policies`, `vc_policies`, `specific_vc_policies`), optional. */
  policies?: Record<string, unknown>;
}

export interface DcqlQuery {
  credentials: DcqlCredentialQuery[];
  credential_sets?: unknown;
}

export interface DcqlCredentialQuery {
  id: string;
  format: string;
  meta?: Record<string, unknown>;
  claims?: DcqlClaimsQuery[];
  require_cryptographic_holder_binding?: boolean;
  [other: string]: unknown;
}

export interface DcqlClaimsQuery {
  id?: string;
  path: Array<string | number | null>;
  values?: unknown[];
  [other: string]: unknown;
}

export interface FireFlyConfig {
  url: string;
  namespace: string;
  apiName: string;
  /** The key FireFly signs `attest` with: an address the contract owner authorised as a verifier. */
  signingKey: string;
  /** Optional `Authorization` header for an authenticating proxy in front of FireFly. */
  authHeader?: string;
  /**
   * The contract API name of the on-chain `TrustedIssuerRegistry` (`FIREFLY_REGISTRY_API`).
   * When set, the bridge asks `isTrusted(issuer, vct)` for every presented credential
   * before it attests, and fails closed when the registry cannot answer. Unset: the
   * verifier's `allowed-issuer` policy is the only issuer check.
   */
  registryApiName?: string;
}

/**
 * The Digital Credentials API path (docs/BRIDGE-API.md, `dc_api`): a second,
 * browser-mediated verifier session per login attempt. Off unless configured.
 */
export interface DcApiConfig {
  /**
   * Origins of the login pages (`https://site.example`, with the port if any): what the
   * browser reports to the wallet and what the verifier expects in the holder binding.
   */
  origins: string[];
  /** walt.id verifier-api2 base URL as browsers reach it; the response route is built from it. */
  verifierPublicUrl: string;
}

export interface Config {
  listenHost: string;
  listenPort: number;
  /** WordPress must send `Authorization: Bearer <authToken>`. */
  authToken: string;
  /** Where the verifier posts session updates; the session id is appended as a path segment. */
  callbackUrl: string;
  /** walt.id verifier-api2 base URL, as the bridge reaches it. */
  verifierUrl: string;
  /** Ask walt.id to sign requests using its configured client id, key and x5c. */
  verifierSignedRequest: boolean;
  firefly: FireFlyConfig;
  queries: Record<string, QueryDefinition>;
  /** `null` when BRIDGE_DC_API_ORIGINS is unset: every `dc_api` is then `null`. */
  dcApi: DcApiConfig | null;
  logLevel: LogLevel;
}

export const SUPPORTED_FORMATS = ['dc+sd-jwt'] as const;
const MIN_TOKEN_LENGTH = 32;

export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const authToken = required(env, 'BRIDGE_AUTH_TOKEN');
  if (authToken.length < MIN_TOKEN_LENGTH) {
    throw new ConfigError(`BRIDGE_AUTH_TOKEN must be at least ${MIN_TOKEN_LENGTH} characters (try: openssl rand -base64 32)`);
  }

  const listenPort = Number.parseInt(env['BRIDGE_PORT'] ?? '8090', 10);
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    throw new ConfigError('BRIDGE_PORT must be a TCP port number');
  }

  const logLevel = env['BRIDGE_LOG_LEVEL'] ?? 'info';
  if (!isLogLevel(logLevel)) {
    throw new ConfigError('BRIDGE_LOG_LEVEL must be one of debug, info, warn, error');
  }

  const callbackUrl = httpUrl(required(env, 'BRIDGE_CALLBACK_URL'), 'BRIDGE_CALLBACK_URL').replace(/\/+$/, '');
  const verifierUrl = httpUrl(required(env, 'VERIFIER_URL'), 'VERIFIER_URL').replace(/\/+$/, '');

  const signedRequest = env['VERIFIER_SIGNED_REQUEST']?.trim() || 'false';
  if (signedRequest !== 'true' && signedRequest !== 'false') {
    throw new ConfigError('VERIFIER_SIGNED_REQUEST must be true or false');
  }

  const firefly: FireFlyConfig = {
    url: httpUrl(required(env, 'FIREFLY_URL'), 'FIREFLY_URL').replace(/\/+$/, ''),
    namespace: env['FIREFLY_NAMESPACE']?.trim() || 'default',
    apiName: env['FIREFLY_API_NAME']?.trim() || 'ssi-login-attestor',
    signingKey: required(env, 'FIREFLY_SIGNING_KEY'),
  };
  const fireflyAuth = env['FIREFLY_AUTH_HEADER']?.trim();
  if (fireflyAuth) {
    firefly.authHeader = fireflyAuth;
  }
  const registryApiName = env['FIREFLY_REGISTRY_API']?.trim();
  if (registryApiName) {
    firefly.registryApiName = registryApiName;
  }

  return {
    listenHost: env['BRIDGE_LISTEN_HOST']?.trim() || '0.0.0.0',
    listenPort,
    authToken,
    callbackUrl,
    verifierUrl,
    verifierSignedRequest: signedRequest === 'true',
    firefly,
    queries: parseQueries(required(env, 'BRIDGE_QUERIES')),
    dcApi: parseDcApi(env),
    logLevel,
  };
}

/**
 * BRIDGE_DC_API_ORIGINS lists the login pages' origins, separated by commas or
 * whitespace; VERIFIER_PUBLIC_URL is then required, because the browser posts
 * the wallet's answer straight to the verifier. An origin is scheme, host and
 * port only (the browser's `location.origin`), and it must be a secure context,
 * as the Digital Credentials API itself requires: https, or http on localhost.
 */
function parseDcApi(env: NodeJS.ProcessEnv): DcApiConfig | null {
  const raw = env['BRIDGE_DC_API_ORIGINS']?.trim();
  if (!raw) {
    return null;
  }
  const origins: string[] = [];
  for (const value of raw.split(/[\s,]+/).filter((item) => item !== '')) {
    const origin = parseOrigin(value);
    if (!origins.includes(origin)) {
      origins.push(origin);
    }
  }
  if (origins.length === 0) {
    return null;
  }
  return {
    origins,
    verifierPublicUrl: httpUrl(required(env, 'VERIFIER_PUBLIC_URL'), 'VERIFIER_PUBLIC_URL').replace(/\/+$/, ''),
  };
}

function parseOrigin(value: string): string {
  const where = `BRIDGE_DC_API_ORIGINS: "${value}"`;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${where} is not an absolute URL`);
  }
  const loopback = url.hostname === 'localhost' || url.hostname.endsWith('.localhost') || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new ConfigError(`${where} must be an https origin (http only on localhost): the Digital Credentials API needs a secure context`);
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '' || url.pathname !== '/') {
    throw new ConfigError(`${where} must be an origin, scheme://host[:port], without a path`);
  }
  // Normalised (lower-case host, no trailing slash): what the browser reports.
  return url.origin;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new ConfigError(`${name} is required`);
  }
  return value;
}

function httpUrl(value: string, name: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigError(`${name} must be an absolute http(s) URL`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ConfigError(`${name} must be an absolute http(s) URL`);
  }
  return value;
}

/**
 * Parses BRIDGE_QUERIES: a JSON object of named queries. The bridge derives the
 * subject from the holder key the presentation is bound to, so every credential
 * query must keep cryptographic holder binding, 0.2 understands SD-JWT VC only,
 * and a query must make the wallet present exactly one credential.
 */
export function parseQueries(json: string): Record<string, QueryDefinition> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error) {
    throw new ConfigError(`BRIDGE_QUERIES is not valid JSON: ${(error as Error).message}`);
  }
  if (!isRecord(parsed) || Object.keys(parsed).length === 0) {
    throw new ConfigError('BRIDGE_QUERIES must be a JSON object of named queries');
  }

  const queries: Record<string, QueryDefinition> = {};
  for (const [name, definition] of Object.entries(parsed)) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
      throw new ConfigError(`BRIDGE_QUERIES: query name "${name}" must be 1-64 letters, digits, "_" or "-"`);
    }
    queries[name] = parseQuery(name, definition);
  }
  if (!queries['default']) {
    throw new ConfigError('BRIDGE_QUERIES must define a query named "default"');
  }
  return queries;
}

function parseQuery(name: string, definition: unknown): QueryDefinition {
  const where = `BRIDGE_QUERIES.${name}`;
  if (!isRecord(definition) || !isRecord(definition['dcql_query'])) {
    throw new ConfigError(`${where} must be an object with a "dcql_query"`);
  }
  const dcql = definition['dcql_query'];
  const credentials = dcql['credentials'];
  if (!Array.isArray(credentials) || credentials.length === 0) {
    throw new ConfigError(`${where}.dcql_query.credentials must be a non-empty array`);
  }
  const seen = new Set<string>();
  for (const credential of credentials) {
    if (!isRecord(credential) || typeof credential['id'] !== 'string' || !/^[A-Za-z0-9_-]+$/.test(credential['id'])) {
      throw new ConfigError(`${where}: every credential query needs an "id" of letters, digits, "_" or "-"`);
    }
    const id = credential['id'];
    if (seen.has(id)) {
      throw new ConfigError(`${where}: credential query id "${id}" is used twice`);
    }
    seen.add(id);
    if (!SUPPORTED_FORMATS.includes(credential['format'] as (typeof SUPPORTED_FORMATS)[number])) {
      throw new ConfigError(`${where}.${id}: format must be one of ${SUPPORTED_FORMATS.join(', ')} (0.2 derives the subject from an SD-JWT VC holder key)`);
    }
    if (credential['require_cryptographic_holder_binding'] === false) {
      throw new ConfigError(`${where}.${id}: require_cryptographic_holder_binding cannot be false, the subject is the bound holder key`);
    }
    if (credential['multiple'] === true) {
      throw new ConfigError(`${where}.${id}: multiple cannot be true, the subject is derived from exactly one presented credential`);
    }
    const claims = credential['claims'];
    if (claims !== undefined) {
      if (!Array.isArray(claims) || claims.length === 0) {
        throw new ConfigError(`${where}.${id}: claims must be a non-empty array when set`);
      }
      for (const claim of claims) {
        if (!isRecord(claim) || !Array.isArray(claim['path']) || claim['path'].length === 0
          || !claim['path'].every((segment) => segment === null || typeof segment === 'string' || (Number.isInteger(segment) && (segment as number) >= 0))) {
          throw new ConfigError(`${where}.${id}: every claims query needs a non-empty "path" of strings, non-negative integers or null`);
        }
      }
    }
  }
  requireOneCredential(where, [...seen], dcql['credential_sets']);
  const policies = definition['policies'];
  if (policies !== undefined && !isRecord(policies)) {
    throw new ConfigError(`${where}.policies must be an object when set`);
  }
  const query: QueryDefinition = { dcql_query: dcql as unknown as DcqlQuery };
  if (policies !== undefined) {
    query.policies = policies;
  }
  return query;
}

/**
 * The bridge derives the login subject and claims from one presented credential
 * (evaluateSession), so a query must make the wallet present exactly one. Under
 * OpenID4VP 1.0 §6.4 every credential query is presented unless `credential_sets`
 * says otherwise, so either the query lists a single credential query, or it has
 * one required credential set whose every option names a single credential query
 * (the wallet then presents one of them). Anything else is refused at start-up
 * rather than silently resolved to the first credential presented.
 */
function requireOneCredential(where: string, ids: string[], credentialSets: unknown): void {
  const dcql = `${where}.dcql_query`;
  if (credentialSets === undefined) {
    if (ids.length !== 1) {
      throw new ConfigError(
        `${dcql} asks the wallet for ${ids.length} credentials (${ids.join(', ')}); the bridge derives the subject from exactly one, so list one credential query, or add one credential_sets entry whose options each name one of them`,
      );
    }
    return;
  }
  if (!Array.isArray(credentialSets) || credentialSets.length !== 1) {
    throw new ConfigError(`${dcql}.credential_sets must be an array of exactly one credential set: every required set adds a presented credential, and the bridge derives the subject from exactly one`);
  }
  const set = credentialSets[0];
  if (!isRecord(set) || !Array.isArray(set['options']) || set['options'].length === 0) {
    throw new ConfigError(`${dcql}.credential_sets[0] must have a non-empty "options" array`);
  }
  if (set['required'] === false) {
    throw new ConfigError(`${dcql}.credential_sets[0]: required cannot be false, the wallet must present exactly one credential`);
  }
  const referenced = new Set<string>();
  for (const option of set['options'] as unknown[]) {
    const id = Array.isArray(option) && option.length === 1 ? option[0] : undefined;
    if (typeof id !== 'string' || !ids.includes(id)) {
      throw new ConfigError(`${dcql}.credential_sets[0]: every option must name exactly one credential query id (one of ${ids.join(', ')}), so that one credential is presented`);
    }
    referenced.add(id);
  }
  const unreferenced = ids.filter((id) => !referenced.has(id));
  if (unreferenced.length > 0) {
    throw new ConfigError(`${dcql}: credential query ${unreferenced.join(', ')} is not an option of credential_sets[0], so the wallet would never be asked for it`);
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
