/**
 * The holder's side of SD-JWT VC: read an issued credential, pick the
 * disclosures a DCQL query asks for, and bind the presentation to the
 * verifier's nonce and audience with a key-binding JWT (IETF SD-JWT, the
 * `kb+jwt` of RFC 9901; SD-JWT VC draft).
 *
 * The holder never changes the issuer's JWT: a presentation is the same JWT,
 * a subset of its disclosures, and the KB-JWT the agent signs.
 */

import { createHash } from 'node:crypto';

import { AgentError, b64url, b64urlDecode, decodeJwt, nowSeconds, signJwt, thumbprintUri } from './jose.mjs';

const HASHES = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' };

/**
 * @typedef {{issuerJwt: string, header: Record<string, unknown>, payload: Record<string, unknown>, disclosures: string[], kbJwt: string | null, alg: string}} SdJwt
 */

/**
 * Splits `<issuer JWT>~<disclosure>~…~` (issued) or `…~<KB-JWT>` (presented).
 *
 * @param {string} compact
 * @returns {SdJwt}
 */
export function parse(compact) {
	if (typeof compact !== 'string' || compact === '') {
		throw new AgentError('empty SD-JWT', 'malformed');
	}
	const parts = compact.trim().split('~');
	const issuerJwt = parts[0];
	const last = parts[parts.length - 1];
	let disclosures;
	let kbJwt = null;
	if (parts.length === 1) {
		disclosures = [];
	} else if (last === '') {
		disclosures = parts.slice(1, -1);
	} else if (last.includes('.')) {
		kbJwt = last;
		disclosures = parts.slice(1, -1);
	} else {
		// An issued SD-JWT without its trailing tilde: tolerated, it is unambiguous.
		disclosures = parts.slice(1);
	}
	const { header, payload } = decodeJwt(issuerJwt);
	const alg = payload._sd_alg === undefined ? 'sha-256' : String(payload._sd_alg);
	if (!(alg in HASHES)) {
		throw new AgentError(`the credential uses an unsupported _sd_alg ${alg}`, 'unsupported');
	}
	return { issuerJwt, header, payload, disclosures, kbJwt, alg };
}

/** base64url(hash(disclosure)), the disclosure being the base64url text itself (RFC 9901 §4.2.4). */
export function digest(disclosure, alg = 'sha-256') {
	return b64url(createHash(HASHES[alg]).update(disclosure, 'ascii').digest());
}

/**
 * @param {string} disclosure
 * @returns {{salt: string, name: string | null, value: unknown}}
 */
export function decodeDisclosure(disclosure) {
	let decoded;
	try {
		decoded = JSON.parse(b64urlDecode(disclosure).toString('utf8'));
	} catch {
		throw new AgentError('a disclosure is not base64url JSON', 'malformed');
	}
	if (!Array.isArray(decoded) || (decoded.length !== 2 && decoded.length !== 3) || typeof decoded[0] !== 'string') {
		throw new AgentError('a disclosure is not [salt, name, value] or [salt, value]', 'malformed');
	}
	return decoded.length === 3
		? { salt: decoded[0], name: String(decoded[1]), value: decoded[2] }
		: { salt: decoded[0], name: null, value: decoded[1] };
}

const pathKey = (path) => JSON.stringify(path);

/**
 * The credential as the issuer meant it, every disclosure applied, plus the
 * disclosures each claim path needs (the claim's own and those of the objects
 * and arrays above it). Decoys and unknown digests are skipped, as a verifier
 * skips them.
 *
 * @param {SdJwt} sdJwt
 * @returns {{claims: Record<string, unknown>, needed: Map<string, string[]>}}
 */
export function resolve(sdJwt) {
	const byDigest = new Map(sdJwt.disclosures.map((d) => [digest(d, sdJwt.alg), d]));
	const needed = new Map();

	function walk(node, path, above) {
		if (Array.isArray(node)) {
			const out = [];
			for (const item of node) {
				if (item !== null && typeof item === 'object' && !Array.isArray(item) && '...' in item) {
					const disclosure = byDigest.get(String(item['...']));
					if (disclosure === undefined) {
						continue;
					}
					const { value } = decodeDisclosure(disclosure);
					const here = [...path, out.length];
					const chain = [...above, disclosure];
					needed.set(pathKey(here), chain);
					out.push(walk(value, here, chain));
				} else {
					out.push(walk(item, [...path, out.length], above));
				}
			}
			return out;
		}
		if (node !== null && typeof node === 'object') {
			const out = {};
			for (const [name, value] of Object.entries(node)) {
				if (name === '_sd' || name === '_sd_alg') {
					continue;
				}
				out[name] = walk(value, [...path, name], above);
			}
			for (const sd of Array.isArray(node._sd) ? node._sd : []) {
				const disclosure = byDigest.get(String(sd));
				if (disclosure === undefined) {
					continue;
				}
				const { name, value } = decodeDisclosure(disclosure);
				if (name === null) {
					throw new AgentError('an object disclosure has no claim name', 'malformed');
				}
				const here = [...path, name];
				const chain = [...above, disclosure];
				needed.set(pathKey(here), chain);
				out[name] = walk(value, here, chain);
			}
			return out;
		}
		return node;
	}

	return { claims: walk(sdJwt.payload, [], []), needed };
}

/** Whether a DCQL claim path (strings, integers, null for every element) matches a concrete path. */
function matches(query, concrete) {
	if (query.length > concrete.length) {
		return false;
	}
	return query.every((element, index) => element === null ? typeof concrete[index] === 'number' : element === concrete[index]);
}

/** The value at a DCQL claim path, or undefined. `null` elements take the first array element that exists. */
function valueAt(claims, path) {
	let node = claims;
	for (const element of path) {
		if (element === null) {
			if (!Array.isArray(node) || node.length === 0) {
				return undefined;
			}
			node = node[0];
		} else if (node !== null && typeof node === 'object' && element in node) {
			node = node[element];
		} else {
			return undefined;
		}
	}
	return node;
}

/**
 * The disclosures to present for the claims a DCQL credential query asks for:
 * for each requested path, the disclosures on the way to it and every
 * disclosure below it; nothing else. No `claims` in the query means the whole
 * credential (OpenID4VP 1.0 §6.3).
 *
 * @param {SdJwt} sdJwt
 * @param {Array<Array<string | number | null>> | undefined} paths
 * @returns {string[]} In the order the issuer listed them.
 */
export function select(sdJwt, paths) {
	if (paths === undefined) {
		return [...sdJwt.disclosures];
	}
	const { claims, needed } = resolve(sdJwt);
	const chosen = new Set();
	for (const path of paths) {
		if (!Array.isArray(path) || path.length === 0) {
			throw new AgentError('a DCQL claim path must be a non-empty array', 'malformed');
		}
		if (valueAt(claims, path) === undefined) {
			throw new AgentError(`the credential has no claim at ${JSON.stringify(path)}`, 'missing_claim');
		}
		for (const [key, chain] of needed) {
			const concrete = JSON.parse(key);
			// The claim itself or something above it (chain prefixes), or something inside it.
			if (matches(concrete, path) || matches(path, concrete)) {
				chain.forEach((d) => chosen.add(d));
			}
		}
	}
	return sdJwt.disclosures.filter((d) => chosen.has(d));
}

/** What the verifier hashes: the presentation up to and including the last `~` before the KB-JWT. */
export function sdHashInput(issuerJwt, disclosures) {
	return [issuerJwt, ...disclosures, ''].join('~');
}

/**
 * The presentation: the issuer's JWT, the chosen disclosures, and a KB-JWT
 * over the verifier's nonce and audience and the hash of what precedes it.
 *
 * @param {SdJwt} sdJwt
 * @param {string[]} disclosures
 * @param {{aud: string, nonce: string, iat?: number}} binding
 * @param {Record<string, string>} holderKey The agent's private JWK.
 */
export function present(sdJwt, disclosures, binding, holderKey) {
	if (typeof binding.aud !== 'string' || binding.aud === '' || typeof binding.nonce !== 'string' || binding.nonce === '') {
		throw new AgentError('a presentation needs the verifier\'s audience and nonce', 'malformed');
	}
	const head = sdHashInput(sdJwt.issuerJwt, disclosures);
	const sdHash = b64url(createHash(HASHES[sdJwt.alg]).update(head, 'ascii').digest());
	const kbJwt = signJwt(
		{ typ: 'kb+jwt' },
		{ iat: binding.iat ?? nowSeconds(), aud: binding.aud, nonce: binding.nonce, sd_hash: sdHash },
		holderKey,
	);
	return head + kbJwt;
}

/**
 * The subject id the bridge derives for this holder (bridge/src/verifier.ts,
 * holderSubjectId): the RFC 9278 thumbprint URI of `cnf.jwk`, or the DID in
 * `cnf.kid` without its fragment. Null when `cnf` is neither.
 */
export function holderSubjectId(cnf) {
	if (cnf === null || typeof cnf !== 'object') {
		return null;
	}
	if (cnf.jwk !== null && typeof cnf.jwk === 'object') {
		try {
			return thumbprintUri(cnf.jwk);
		} catch {
			return null;
		}
	}
	if (typeof cnf.kid === 'string' && cnf.kid.startsWith('did:')) {
		const did = cnf.kid.split('#', 1)[0] ?? '';
		return did.length > 4 ? did : null;
	}
	return null;
}
