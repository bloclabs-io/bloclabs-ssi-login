/**
 * Presenting to the verifier: OpenID for Verifiable Presentations 1.0 with
 * DCQL, as a wallet with one SD-JWT VC and no screen to show the request on.
 *
 * The agent fetches the request object behind the `request_uri` of the wallet
 * URL that *its own* `/agent/initiate` call returned, and nothing else (ADR
 * 0007 threat A2: an attacker who hands this agent a wallet URL hands it the
 * attacker's attempt). Before it presents, it checks who is asking:
 *
 * - the request's `client_id` is the one the wallet URL named, and the one
 *   the operator pinned, if any;
 * - a `redirect_uri:` client id names exactly the `response_uri` (also in the
 *   pre-1.0 form, a bare URI with `client_id_scheme: redirect_uri`);
 * - an `x509_san_dns:` or `x509_hash:` client id comes in a signed request
 *   whose `x5c` leaf certificate carries that DNS name or has that hash, the
 *   signature verifies under the leaf's key, and the `response_uri` is on
 *   that host;
 * - a client id of any other scheme (`did:`, a pre-registered name) is
 *   presented to only when the operator pinned exactly that id;
 * - the response goes back by `direct_post`, in clear. Encrypted responses
 *   (`direct_post.jwt`) are not supported here.
 */

import { AgentError, certificateHash, decodeJwt, leafCertificate, verifyJwt } from './jose.mjs';
import { describe, getJson, httpUrl, isRecord, postForm, request } from './http.mjs';

const WALLET_SCHEMES = ['openid4vp:', 'https:', 'haip:', 'openid-vc:'];

/**
 * @param {string} walletUrl
 * @returns {{clientId: string | null, requestUri: string | null, request: string | null}}
 */
export function parseWalletUrl(walletUrl) {
	let url;
	try {
		url = new URL(walletUrl);
	} catch {
		throw new AgentError('the wallet URL does not parse', 'malformed');
	}
	if (!WALLET_SCHEMES.includes(url.protocol)) {
		throw new AgentError(`unsupported wallet URL scheme ${url.protocol}`, 'unsupported');
	}
	return {
		clientId: url.searchParams.get('client_id'),
		requestUri: url.searchParams.get('request_uri'),
		request: url.searchParams.get('request'),
	};
}

/**
 * The authorization request object: JSON when the verifier serves it unsigned,
 * a JWS (`oauth-authz-req+jwt`) when signed. A signed request is verified
 * against its `x5c` leaf here; whether that leaf is the right one is
 * checkVerifier()'s question.
 *
 * @returns {Promise<{request: Record<string, unknown>, leaf: import('node:crypto').X509Certificate | null, clientId: string | null}>}
 */
export async function fetchRequest(walletUrl, options = {}) {
	const { fetchImpl } = options;
	const parsed = parseWalletUrl(walletUrl);
	let raw;
	if (parsed.request !== null) {
		raw = parsed.request;
	} else if (parsed.requestUri !== null) {
		const answer = await request(httpUrl(parsed.requestUri, 'request_uri'), {
			headers: { accept: 'application/oauth-authz-req+jwt, application/json' },
			fetchImpl,
			who: 'the verifier',
		});
		if (answer.status !== 200) {
			throw new AgentError(`the verifier answered HTTP ${answer.status} for the request object (${describe(parsed.requestUri)})`, 'http_' + answer.status);
		}
		raw = answer.text;
	} else {
		throw new AgentError('the wallet URL carries neither request_uri nor request', 'malformed');
	}

	const text = raw.trim();
	if (text.startsWith('{')) {
		let json;
		try {
			json = JSON.parse(text);
		} catch {
			throw new AgentError('the unsigned request object is not JSON', 'malformed');
		}
		if (!isRecord(json)) {
			throw new AgentError('the request object is not a JSON object', 'malformed');
		}
		return { request: json, leaf: null, clientId: parsed.clientId };
	}

	const { header, payload } = decodeJwt(text);
	if (header.alg === 'none') {
		return { request: payload, leaf: null, clientId: parsed.clientId };
	}
	const leaf = leafCertificate(header.x5c);
	if (!verifyJwt(text, leaf.publicKey)) {
		throw new AgentError('the signed request object does not verify under its x5c leaf certificate', 'bad_signature');
	}
	return { request: payload, leaf, clientId: parsed.clientId };
}

/**
 * Refuses to present to anyone but the verifier the agent set out to present to.
 *
 * @param {Record<string, unknown>} req
 * @param {{clientId: string | null, leaf: import('node:crypto').X509Certificate | null, expected?: string | null}} context
 * @returns {{clientId: string, responseUri: string, nonce: string, state: string | null}}
 */
export function checkVerifier(req, context) {
	const clientId = req.client_id;
	if (typeof clientId !== 'string' || clientId === '') {
		throw new AgentError('the request object names no client_id', 'malformed');
	}
	if (context.clientId !== null && context.clientId !== clientId) {
		throw new AgentError('the request object names another verifier than the wallet URL did', 'verifier_mismatch');
	}
	if (context.expected && context.expected !== clientId) {
		throw new AgentError(`the verifier is ${clientId}, not the pinned ${context.expected}`, 'verifier_mismatch');
	}
	if (typeof req.response_type !== 'string' || !req.response_type.split(' ').includes('vp_token')) {
		throw new AgentError('the request does not ask for a vp_token', 'unsupported');
	}
	const mode = req.response_mode ?? 'fragment';
	if (mode !== 'direct_post') {
		throw new AgentError(`response_mode ${String(mode)} is not supported; this agent answers direct_post in clear`, 'unsupported');
	}
	const responseUri = httpUrl(req.response_uri, 'response_uri');
	if (typeof req.nonce !== 'string' || req.nonce === '') {
		throw new AgentError('the request carries no nonce', 'malformed');
	}

	const colon = clientId.indexOf(':');
	let scheme = colon === -1 ? '' : clientId.slice(0, colon);
	let value = colon === -1 ? clientId : clientId.slice(colon + 1);
	if ((scheme === 'http' || scheme === 'https') && (req.client_id_scheme === 'redirect_uri' || req.client_id_scheme === undefined)) {
		// Drafts before 1.0 carried the scheme in `client_id_scheme` and the bare URI in `client_id`.
		scheme = 'redirect_uri';
		value = clientId;
	}
	if (scheme === 'redirect_uri') {
		if (value.replace(/\/+$/, '') !== responseUri.replace(/\/+$/, '')) {
			throw new AgentError('a redirect_uri client id must name the response_uri', 'verifier_mismatch');
		}
	} else if (scheme === 'x509_san_dns' || scheme === 'x509_hash') {
		if (context.leaf === null) {
			throw new AgentError(`an ${scheme} client id needs a signed request`, 'verifier_mismatch');
		}
		const host = new URL(responseUri).hostname;
		if (scheme === 'x509_san_dns') {
			if (context.leaf.checkHost(value) === undefined) {
				throw new AgentError(`the request's certificate is not issued to ${value}`, 'verifier_mismatch');
			}
			if (host !== value) {
				throw new AgentError(`the response_uri is on ${host}, not on the verifier ${value}`, 'verifier_mismatch');
			}
		} else if (certificateHash(context.leaf) !== value) {
			throw new AgentError('the request\'s certificate is not the one the client id names', 'verifier_mismatch');
		}
	} else if (!context.expected) {
		throw new AgentError(`client id scheme ${scheme === '' ? '(none)' : scheme} is not one this agent can check; it presents to redirect_uri, x509_san_dns and x509_hash verifiers, or to the client id pinned with --verifier`, 'unsupported');
	}
	// Any other scheme is accepted only because the operator pinned exactly this
	// client id. An unsigned request proves no more than a redirect_uri one does.

	return { clientId, responseUri, nonce: req.nonce, state: typeof req.state === 'string' ? req.state : null };
}

/**
 * The one credential query this agent can satisfy: `dc+sd-jwt` (or the older
 * `vc+sd-jwt`), with no `vct_values` or ones that name the credential's type.
 *
 * @returns {{id: string, paths: Array<Array<string | number | null>> | undefined}}
 */
export function chooseCredentialQuery(dcql, vct) {
	const credentials = isRecord(dcql) && Array.isArray(dcql.credentials) ? dcql.credentials : [];
	for (const query of credentials) {
		if (!isRecord(query) || typeof query.id !== 'string') {
			continue;
		}
		if (query.format !== 'dc+sd-jwt' && query.format !== 'vc+sd-jwt') {
			continue;
		}
		const values = isRecord(query.meta) && Array.isArray(query.meta.vct_values) ? query.meta.vct_values : null;
		if (values !== null && (vct === null || !values.includes(vct))) {
			continue;
		}
		let paths;
		if (Array.isArray(query.claims)) {
			paths = query.claims.map((claim) => {
				if (!isRecord(claim) || !Array.isArray(claim.path)) {
					throw new AgentError('a DCQL claim has no path', 'malformed');
				}
				return claim.path;
			});
		}
		return { id: query.id, paths };
	}
	throw new AgentError(`the verifier asks for no SD-JWT VC credential this agent holds${vct === null ? '' : ` (vct ${vct})`}`, 'no_matching_query');
}

/**
 * OpenID4VP 1.0: a JSON object from credential query id to the presentations
 * for it, one here. `form: 'string'` sends the id's value as a bare string
 * instead of a one-element array, for verifiers that read the older shape.
 */
export function vpToken(queryId, presentation, form = 'array') {
	return JSON.stringify({ [queryId]: form === 'string' ? presentation : [presentation] });
}

/**
 * `direct_post`: the vp_token and the state, form-encoded, to the response_uri.
 */
export async function respond(responseUri, token, state, options = {}) {
	const answer = await postForm(responseUri, { vp_token: token, state }, { fetchImpl: options.fetchImpl, who: 'the verifier' });
	if (answer.status < 200 || answer.status >= 300) {
		throw new AgentError(`the verifier refused the presentation: HTTP ${answer.status}${detail(answer.json)}`, 'presentation_refused');
	}
	return isRecord(answer.json) ? answer.json : {};
}

function detail(json) {
	if (!isRecord(json)) {
		return '';
	}
	const parts = [json.error, json.error_description, json.message].filter((p) => typeof p === 'string');
	return parts.length === 0 ? '' : ` (${parts.join(': ')})`;
}

export { getJson };
