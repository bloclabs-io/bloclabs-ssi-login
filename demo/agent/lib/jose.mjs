/**
 * The JOSE pieces the agent needs, on Node's crypto module alone: base64url,
 * a P-256 key as a JWK, its RFC 7638 thumbprint and RFC 9278 thumbprint URI,
 * `did:jwk`, compact ES256 JWS, and the X.509 checks a signed OpenID4VP
 * request asks for.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, X509Certificate } from 'node:crypto';

export class AgentError extends Error {
	/**
	 * @param {string} message What went wrong, for a person.
	 * @param {string} code    A stable word for scripts (`verifier_mismatch`, `refused`, …).
	 */
	constructor(message, code = 'agent_error') {
		super(message);
		this.code = code;
	}
}

export function b64url(input) {
	return Buffer.from(input).toString('base64url');
}

export function b64urlDecode(text) {
	if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
		throw new AgentError('not base64url', 'malformed');
	}
	return Buffer.from(text, 'base64url');
}

export function b64urlJson(value) {
	return b64url(JSON.stringify(value));
}

export function decodeJson(text) {
	try {
		return JSON.parse(b64urlDecode(text).toString('utf8'));
	} catch (error) {
		throw new AgentError(`not base64url JSON: ${error.message}`, 'malformed');
	}
}

/** A fresh P-256 key, private part included. */
export function generateKey() {
	const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
	const jwk = privateKey.export({ format: 'jwk' });
	return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d };
}

export function publicJwk(jwk) {
	return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/** RFC 7638: SHA-256 of the required members, in lexicographic order, no whitespace. */
export function thumbprint(jwk) {
	if (jwk.kty !== 'EC' || typeof jwk.crv !== 'string' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
		throw new AgentError('only EC keys have a thumbprint here', 'malformed');
	}
	const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
	return b64url(createHash('sha256').update(canonical).digest());
}

/** RFC 9278. The bridge derives a holder's subject id from this when `cnf` carries a JWK. */
export function thumbprintUri(jwk) {
	return `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${thumbprint(jwk)}`;
}

export function didJwk(jwk) {
	return `did:jwk:${b64urlJson(publicJwk(jwk))}`;
}

/** The one verification method a did:jwk document has. */
export function didJwkKeyId(jwk) {
	return `${didJwk(jwk)}#0`;
}

/**
 * Compact JWS, ES256 (the JOSE raw r||s signature, not DER).
 *
 * @param {Record<string, unknown>} header  Without `alg`; `typ`, `kid` or `jwk` as the caller needs.
 * @param {Record<string, unknown>} payload
 * @param {Record<string, string>}  jwk     The private key.
 */
export function signJwt(header, payload, jwk) {
	const key = createPrivateKey({ key: jwk, format: 'jwk' });
	const signingInput = `${b64urlJson({ ...header, alg: 'ES256' })}.${b64urlJson(payload)}`;
	const signature = sign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' });
	return `${signingInput}.${b64url(signature)}`;
}

/**
 * @param {string} jws
 * @returns {{header: Record<string, unknown>, payload: Record<string, unknown>, signature: string, signingInput: string}}
 */
export function decodeJwt(jws) {
	const parts = typeof jws === 'string' ? jws.split('.') : [];
	if (parts.length !== 3) {
		throw new AgentError('not a compact JWS', 'malformed');
	}
	const header = decodeJson(parts[0]);
	const payload = decodeJson(parts[1]);
	if (header === null || typeof header !== 'object' || payload === null || typeof payload !== 'object') {
		throw new AgentError('a JWS header and payload must be JSON objects', 'malformed');
	}
	return { header, payload, signature: parts[2], signingInput: `${parts[0]}.${parts[1]}` };
}

/**
 * @param {string} jws
 * @param {import('node:crypto').KeyObject | Record<string, string>} publicKey A KeyObject or a public JWK.
 */
export function verifyJwt(jws, publicKey) {
	const { header, signingInput, signature } = decodeJwt(jws);
	if (header.alg !== 'ES256') {
		throw new AgentError(`unsupported JWS algorithm ${String(header.alg)}; this agent verifies ES256`, 'unsupported');
	}
	const key = typeof publicKey === 'object' && 'kty' in publicKey ? createPublicKey({ key: publicKey, format: 'jwk' }) : publicKey;
	return verify('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' }, b64urlDecode(signature));
}

/**
 * The leaf certificate of an `x5c` header (standard base64 DER, leaf first).
 */
export function leafCertificate(x5c) {
	if (!Array.isArray(x5c) || x5c.length === 0 || typeof x5c[0] !== 'string') {
		throw new AgentError('the signed request carries no x5c certificate chain', 'malformed');
	}
	try {
		return new X509Certificate(Buffer.from(x5c[0], 'base64'));
	} catch (error) {
		throw new AgentError(`the x5c leaf certificate does not parse: ${error.message}`, 'malformed');
	}
}

/** `x509_hash:` client ids: base64url(SHA-256(leaf DER)). */
export function certificateHash(certificate) {
	return b64url(createHash('sha256').update(certificate.raw).digest());
}

export function nowSeconds() {
	return Math.floor(Date.now() / 1000);
}
