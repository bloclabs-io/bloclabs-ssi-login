/**
 * Receiving the agent credential: the OpenID for Verifiable Credential
 * Issuance pre-authorized code flow, as a holder with one key and no UI.
 *
 * 1. Resolve the credential offer (by reference or by value).
 * 2. Read the issuer's metadata, inserting `/.well-known/openid-credential-issuer`
 *    between host and path as OpenID4VCI 1.0 says, then the authorization server's.
 * 3. Exchange the pre-authorized code for an access token.
 * 4. Fetch a nonce (`nonce_endpoint`, 1.0) or take `c_nonce` from the token
 *    answer (older drafts).
 * 5. Sign the proof of possession of the agent's key and ask for the credential.
 *    The 1.0 request shape (`credential_configuration_id` and `proofs`) is tried
 *    first; an issuer that refuses it with 400 gets the draft 13 shape.
 *
 * The credential comes back bound to the agent's key in `cnf`: that key is who
 * the agent is, for the bridge and for WordPress.
 */

import { AgentError, didJwkKeyId, nowSeconds, publicJwk, signJwt } from './jose.mjs';
import { describe, getJson, httpUrl, isRecord, postForm, postJson, request } from './http.mjs';

export const PRE_AUTHORIZED = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const OFFER_SCHEMES = ['openid-credential-offer:', 'haip:'];

/**
 * The offer object behind a `openid-credential-offer://` URL, a bare URL to the
 * offer, or the offer's JSON itself.
 */
export async function resolveOffer(text, options = {}) {
	const { fetchImpl } = options;
	const trimmed = String(text ?? '').trim();
	if (trimmed === '') {
		throw new AgentError('no credential offer given', 'malformed');
	}
	if (trimmed.startsWith('{')) {
		return offerObject(JSON.parse(trimmed));
	}
	let url;
	try {
		url = new URL(trimmed);
	} catch {
		throw new AgentError('the credential offer is neither a URL nor JSON', 'malformed');
	}
	if (OFFER_SCHEMES.includes(url.protocol)) {
		const byReference = url.searchParams.get('credential_offer_uri');
		const byValue = url.searchParams.get('credential_offer');
		if (byReference !== null) {
			return offerObject(await getJson(httpUrl(byReference, 'credential_offer_uri'), { fetchImpl, who: 'the issuer' }));
		}
		if (byValue !== null) {
			return offerObject(JSON.parse(byValue));
		}
		throw new AgentError('the credential offer URL carries neither credential_offer_uri nor credential_offer', 'malformed');
	}
	if (url.protocol === 'https:' || url.protocol === 'http:') {
		return offerObject(await getJson(trimmed, { fetchImpl, who: 'the issuer' }));
	}
	throw new AgentError(`unsupported credential offer scheme ${url.protocol}`, 'unsupported');
}

function offerObject(offer) {
	if (!isRecord(offer)) {
		throw new AgentError('the credential offer is not a JSON object', 'malformed');
	}
	const issuer = httpUrl(offer.credential_issuer, 'credential_issuer');
	const ids = Array.isArray(offer.credential_configuration_ids) ? offer.credential_configuration_ids.filter((id) => typeof id === 'string' && id !== '') : [];
	if (ids.length === 0) {
		throw new AgentError('the credential offer names no credential_configuration_ids', 'malformed');
	}
	const grant = isRecord(offer.grants) ? offer.grants[PRE_AUTHORIZED] : undefined;
	if (!isRecord(grant) || typeof grant['pre-authorized_code'] !== 'string' || grant['pre-authorized_code'] === '') {
		throw new AgentError('the credential offer has no pre-authorized code; this agent drives no authorization code flow', 'unsupported');
	}
	return {
		issuer,
		configurationIds: ids,
		preAuthorizedCode: grant['pre-authorized_code'],
		txCode: isRecord(grant.tx_code) ? grant.tx_code : null,
		authorizationServer: typeof grant.authorization_server === 'string' ? grant.authorization_server : null,
	};
}

/**
 * OpenID4VCI 1.0 §11.2.2: for an issuer identifier with a path, the well-known
 * suffix goes between host and path. The plain form follows, for issuers that
 * serve it there.
 */
export function wellKnownCandidates(base, suffix) {
	const url = new URL(base);
	const path = url.pathname.replace(/\/+$/, '');
	const candidates = [`${url.origin}/.well-known/${suffix}${path}`];
	if (path !== '') {
		candidates.push(`${url.origin}${path}/.well-known/${suffix}`);
	}
	return candidates;
}

async function firstJson(candidates, options) {
	let last = null;
	for (const url of candidates) {
		try {
			return await getJson(url, options);
		} catch (error) {
			last = error;
		}
	}
	throw last ?? new AgentError('no metadata URL to try', 'malformed');
}

export async function issuerMetadata(issuer, options = {}) {
	const metadata = await firstJson(wellKnownCandidates(issuer, 'openid-credential-issuer'), { fetchImpl: options.fetchImpl, who: 'the issuer' });
	if (typeof metadata.credential_issuer === 'string' && metadata.credential_issuer.replace(/\/+$/, '') !== issuer) {
		throw new AgentError('the issuer metadata names another credential_issuer than the offer', 'verifier_mismatch');
	}
	return metadata;
}

export async function authorizationServerMetadata(server, options = {}) {
	try {
		return await firstJson(
			[...wellKnownCandidates(server, 'oauth-authorization-server'), ...wellKnownCandidates(server, 'openid-configuration')],
			{ fetchImpl: options.fetchImpl, who: 'the authorization server' },
		);
	} catch {
		// Issuers that publish no server metadata still serve the usual endpoints.
		return null;
	}
}

/**
 * @param {string} offerText                 The offer as the issuer printed it.
 * @param {Record<string, string>} key       The agent's private JWK.
 * @param {{fetchImpl?: typeof fetch, log?: (line: string) => void, txCode?: string, proofKey?: 'did' | 'jwk'}} options
 * @returns {Promise<{credential: string, issuer: string, configurationId: string, vct: string | null}>}
 */
export async function receive(offerText, key, options = {}) {
	const { fetchImpl, log = () => {}, proofKey = 'did' } = options;
	const offer = await resolveOffer(offerText, { fetchImpl });
	log(`offer from ${offer.issuer} for ${offer.configurationIds.join(', ')}`);
	if (offer.txCode !== null && !options.txCode) {
		throw new AgentError('the offer requires a transaction code (tx_code); pass it with --tx-code', 'tx_code');
	}

	const metadata = await issuerMetadata(offer.issuer, { fetchImpl });
	const credentialEndpoint = httpUrl(metadata.credential_endpoint ?? `${offer.issuer}/credential`, 'credential_endpoint');
	const servers = Array.isArray(metadata.authorization_servers) ? metadata.authorization_servers.filter((s) => typeof s === 'string') : [];
	const server = httpUrl(offer.authorizationServer ?? servers[0] ?? offer.issuer, 'authorization_server');
	const serverMetadata = await authorizationServerMetadata(server, { fetchImpl });
	const tokenEndpoint = httpUrl(serverMetadata?.token_endpoint ?? `${server}/token`, 'token_endpoint');

	const tokenAnswer = await postForm(tokenEndpoint, {
		grant_type: PRE_AUTHORIZED,
		'pre-authorized_code': offer.preAuthorizedCode,
		tx_code: options.txCode,
	}, { fetchImpl, who: 'the issuer\'s token endpoint' });
	if (tokenAnswer.status !== 200 || !isRecord(tokenAnswer.json) || typeof tokenAnswer.json.access_token !== 'string') {
		throw new AgentError(`the token endpoint refused the pre-authorized code: HTTP ${tokenAnswer.status} ${errorOf(tokenAnswer.json)}`, 'token_refused');
	}
	const accessToken = tokenAnswer.json.access_token;
	log('access token received');

	let nonce = typeof tokenAnswer.json.c_nonce === 'string' ? tokenAnswer.json.c_nonce : null;
	if (typeof metadata.nonce_endpoint === 'string') {
		const nonceAnswer = await request(httpUrl(metadata.nonce_endpoint, 'nonce_endpoint'), { method: 'POST', headers: { accept: 'application/json' }, fetchImpl, who: 'the issuer\'s nonce endpoint' });
		if (nonceAnswer.status !== 200 || !isRecord(nonceAnswer.json) || typeof nonceAnswer.json.c_nonce !== 'string') {
			throw new AgentError(`the nonce endpoint answered HTTP ${nonceAnswer.status}`, 'nonce');
		}
		nonce = nonceAnswer.json.c_nonce;
	}

	const configurationId = offer.configurationIds[0];
	const configurations = isRecord(metadata.credential_configurations_supported) ? metadata.credential_configurations_supported : {};
	const configuration = isRecord(configurations[configurationId]) ? configurations[configurationId] : {};
	const vct = typeof configuration.vct === 'string' ? configuration.vct : null;

	const proofHeader = { typ: 'openid4vci-proof+jwt' };
	if (proofKey === 'jwk') {
		proofHeader.jwk = publicJwk(key);
	} else {
		proofHeader.kid = didJwkKeyId(key);
	}
	const proofPayload = { aud: offer.issuer, iat: nowSeconds() };
	if (nonce !== null) {
		proofPayload.nonce = nonce;
	}
	const proof = signJwt(proofHeader, proofPayload, key);

	const headers = { authorization: `Bearer ${accessToken}` };
	let answer = await postJson(credentialEndpoint, { credential_configuration_id: configurationId, proofs: { jwt: [proof] } }, { fetchImpl, headers, who: 'the issuer\'s credential endpoint' });
	if (answer.status === 400) {
		log('the issuer refused the OpenID4VCI 1.0 request shape; trying the draft 13 shape');
		answer = await postJson(credentialEndpoint, {
			format: typeof configuration.format === 'string' ? configuration.format : 'dc+sd-jwt',
			...(vct === null ? {} : { vct }),
			proof: { proof_type: 'jwt', jwt: proof },
		}, { fetchImpl, headers, who: 'the issuer\'s credential endpoint' });
	}
	if (answer.status < 200 || answer.status >= 300 || !isRecord(answer.json)) {
		throw new AgentError(`the credential endpoint answered HTTP ${answer.status} ${errorOf(answer.json)}`, 'credential_refused');
	}
	const credential = credentialOf(answer.json);
	if (credential === null) {
		if (answer.json.transaction_id !== undefined) {
			throw new AgentError('the issuer deferred the credential; this agent does not poll deferred issuance', 'unsupported');
		}
		throw new AgentError(`the credential endpoint answered without a credential (${describe(credentialEndpoint)})`, 'malformed');
	}
	log('credential received');
	return { credential, issuer: offer.issuer, configurationId, vct };
}

function credentialOf(body) {
	if (typeof body.credential === 'string') {
		return body.credential;
	}
	if (Array.isArray(body.credentials)) {
		const first = body.credentials[0];
		if (typeof first === 'string') {
			return first;
		}
		if (isRecord(first) && typeof first.credential === 'string') {
			return first.credential;
		}
	}
	return null;
}

function errorOf(json) {
	if (!isRecord(json)) {
		return '';
	}
	const parts = [json.error, json.error_description, json.message].filter((p) => typeof p === 'string');
	return parts.length === 0 ? '' : `(${parts.join(': ')})`;
}
