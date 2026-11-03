/**
 * Hashes and commitments shared with the WordPress plugin and the attestor contract.
 *
 * The plugin recomputes `subjectCommitment` at completion (Attestation::subject_commitment)
 * and compares `presentationHash` with the on-chain value, so these definitions are part of
 * the contract in docs/BRIDGE-API.md.
 */

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

export const ZERO_HASH = '0'.repeat(64);

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * sha256(lowercase hex correlation id ":" blinding secret ":" subject id), as docs/adr/0004
 * defines it. The correlation id is public on chain; the blinding secret is random per attempt
 * and known to WordPress and the bridge only, so nobody can test a guessed subject against
 * an attestation (#25).
 */
export function subjectCommitment(correlationIdHex: string, blindingSecret: string, subjectId: string): string {
  return sha256Hex(correlationIdHex.toLowerCase() + ':' + blindingSecret + ':' + subjectId);
}

/**
 * Canonical JSON (RFC 8785): sorted object keys, no whitespace, JSON string escaping.
 * Used to hash the `vp_token` map the verifier recorded, so the hash does not depend on
 * how either side happens to serialise JSON.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
      throw new TypeError('Value cannot be represented as JSON');
    }
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new TypeError('Non-finite numbers cannot be represented as JSON');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalJson(item)).join(',') + ']';
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(record[key])).join(',') + '}';
}

/** Lowercase hex SHA-256 of the canonical JSON of a value. */
export function presentationHash(vpToken: unknown): string {
  return sha256Hex(canonicalJson(vpToken));
}

const THUMBPRINT_MEMBERS: Record<string, readonly string[]> = {
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x'],
  RSA: ['e', 'kty', 'n'],
};

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export function jwkThumbprint(jwk: Record<string, unknown>): string {
  const kty = typeof jwk['kty'] === 'string' ? jwk['kty'] : '';
  const members = THUMBPRINT_MEMBERS[kty];
  if (!members) {
    throw new Error(`Unsupported JWK key type for a thumbprint: ${kty || '(none)'}`);
  }
  const parts: string[] = [];
  for (const member of members) {
    const value = jwk[member];
    if (typeof value !== 'string' || value === '') {
      throw new Error(`JWK is missing the required member "${member}"`);
    }
    parts.push(JSON.stringify(member) + ':' + JSON.stringify(value));
  }
  return createHash('sha256')
    .update('{' + parts.join(',') + '}')
    .digest('base64url');
}

/** RFC 9278 JWK Thumbprint URI, the stable holder identifier for a `cnf.jwk` holder key. */
export function jwkThumbprintUri(jwk: Record<string, unknown>): string {
  return 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' + jwkThumbprint(jwk);
}

/** Compares two secrets without leaking their length or where they differ. */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = createHash('sha256').update(a, 'utf8').digest();
  const right = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(left, right) && a.length === b.length;
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function newRequestId(): string {
  return randomUUID();
}
