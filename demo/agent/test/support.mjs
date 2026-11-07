/**
 * Stand-ins for the three services the agent talks to, as real HTTP servers on
 * loopback: a walt.id-shaped issuer (OpenID4VCI, pre-authorized code), a
 * verifier (OpenID4VP request object and direct_post response, checking the
 * key-binding JWT the way a verifier must), and WordPress with the agent routes
 * of ADR 0007. Plus a small SD-JWT VC issuer for fixtures.
 */

import { createServer } from 'node:http';
import { randomBytes, createPrivateKey, createPublicKey, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { b64url, b64urlJson, decodeJson, decodeJwt, didJwkKeyId, generateKey, publicJwk, signJwt, thumbprintUri, verifyJwt } from '../lib/jose.mjs';
import { decodeDisclosure, digest, parse, resolve, sdHashInput } from '../lib/sdjwt.mjs';

export const ISSUER_KEY = generateKey();
export const ISSUER_DID = `did:jwk:${b64urlJson(publicJwk(ISSUER_KEY))}`;
export const AGENT_VCT = 'http://issuer.test/openid4vci/agent';
export const ACTS_FOR = 'did:key:z6MkPrincipal';

const salt = () => b64url(randomBytes(16));

/**
 * An SD-JWT VC with top-level selectively disclosable claims, and optionally one
 * nested object whose own members are selectively disclosable.
 *
 * @param {{claims: Record<string, unknown>, sd?: string[], nestedSd?: Record<string, string[]>, holder: {kid?: string, jwk?: object},
 *          vct?: string, exp?: number, decoys?: number, issuerKey?: object, iss?: string, alg?: string}} options
 */
export function issueSdJwt(options) {
	const { claims, sd = [], nestedSd = {}, holder, vct = AGENT_VCT, decoys = 1, issuerKey = ISSUER_KEY, iss = ISSUER_DID } = options;
	const now = Math.floor(Date.now() / 1000);
	const disclosures = [];
	const payload = { iss, vct, iat: now, exp: options.exp ?? now + 3600, cnf: holder, _sd_alg: options.alg ?? 'sha-256' };
	const topDigests = [];
	for (const [name, value] of Object.entries(claims)) {
		let stored = value;
		if (name in nestedSd && value !== null && typeof value === 'object') {
			const inner = {};
			const innerDigests = [];
			for (const [member, memberValue] of Object.entries(value)) {
				if (nestedSd[name].includes(member)) {
					const d = b64urlJson([salt(), member, memberValue]);
					disclosures.push(d);
					innerDigests.push(digest(d));
				} else {
					inner[member] = memberValue;
				}
			}
			inner._sd = innerDigests.sort();
			stored = inner;
		}
		if (sd.includes(name)) {
			const d = b64urlJson([salt(), name, stored]);
			disclosures.push(d);
			topDigests.push(digest(d));
		} else {
			payload[name] = stored;
		}
	}
	for (let i = 0; i < decoys; i += 1) {
		topDigests.push(digest(b64url(randomBytes(16))));
	}
	payload._sd = topDigests.sort();
	const jwt = signJwt({ typ: 'dc+sd-jwt', kid: `${iss}#0` }, payload, issuerKey);
	return `${jwt}~${disclosures.join('~')}${disclosures.length > 0 ? '~' : ''}`;
}

/** The holder key a `cnf` names: an inline JWK or a did:jwk kid. */
export function holderKeyOf(cnf) {
	if (cnf && cnf.jwk) {
		return cnf.jwk;
	}
	if (cnf && typeof cnf.kid === 'string' && cnf.kid.startsWith('did:jwk:')) {
		return decodeJson(cnf.kid.slice('did:jwk:'.length).split('#')[0]);
	}
	throw new Error('cnf names no key this test resolves');
}

/**
 * What a verifier must check on an SD-JWT VC presentation. Throws on the first failure.
 *
 * @returns {{claims: Record<string, unknown>, disclosed: string[], kb: Record<string, unknown>}}
 */
export function verifyPresentation(presentation, { clientId, nonce, issuerKey = ISSUER_KEY }) {
	const sdJwt = parse(presentation);
	if (sdJwt.kbJwt === null) {
		throw new Error('no key-binding JWT');
	}
	if (!verifyJwt(sdJwt.issuerJwt, publicJwk(issuerKey))) {
		throw new Error('issuer signature');
	}
	const kb = decodeJwt(sdJwt.kbJwt);
	if (kb.header.typ !== 'kb+jwt') {
		throw new Error('kb typ');
	}
	if (!verifyJwt(sdJwt.kbJwt, holderKeyOf(sdJwt.payload.cnf))) {
		throw new Error('kb signature');
	}
	if (kb.payload.aud !== clientId) {
		throw new Error(`kb aud ${kb.payload.aud} is not ${clientId}`);
	}
	if (kb.payload.nonce !== nonce) {
		throw new Error('kb nonce');
	}
	if (typeof kb.payload.iat !== 'number') {
		throw new Error('kb iat');
	}
	const expected = b64url(createHash('sha256').update(sdHashInput(sdJwt.issuerJwt, sdJwt.disclosures), 'ascii').digest());
	if (kb.payload.sd_hash !== expected) {
		throw new Error('sd_hash');
	}
	// Every disclosure must hang off a digest somewhere in the payload tree.
	const digests = new Set();
	const collect = (node) => {
		if (Array.isArray(node)) {
			node.forEach(collect);
		} else if (node && typeof node === 'object') {
			(node._sd ?? []).forEach((d) => digests.add(d));
			if ('...' in node) {
				digests.add(node['...']);
			}
			Object.values(node).forEach(collect);
		}
	};
	collect(sdJwt.payload);
	for (const d of sdJwt.disclosures) {
		if (!digests.has(digest(d, sdJwt.alg))) {
			// Could belong to a disclosed nested object: collect from decoded disclosures too.
			sdJwt.disclosures.forEach((other) => collect(decodeDisclosure(other).value));
			if (!digests.has(digest(d, sdJwt.alg))) {
				throw new Error('a disclosure matches no digest');
			}
		}
	}
	const { claims } = resolve(sdJwt);
	return { claims, disclosed: sdJwt.disclosures.map((d) => decodeDisclosure(d).name), kb: kb.payload };
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		req.on('data', (c) => chunks.push(c));
		req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
		req.on('error', reject);
	});
}

function send(res, status, body, type = 'application/json') {
	const text = typeof body === 'string' ? body : JSON.stringify(body);
	res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(text) });
	res.end(text);
}

function listen(handler) {
	const server = createServer((req, res) => {
		handler(req, res).catch((error) => send(res, 500, { error: 'server_error', error_description: error.message }));
	});
	return new Promise((resolve) => {
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address();
			resolve({ server, url: `http://127.0.0.1:${port}`, close: () => new Promise((done) => server.close(done)) });
		});
	});
}

/**
 * The issuer: management API plus OpenID4VCI. `shape` is `final` (1.0:
 * nonce endpoint, `proofs`, `credentials[]`) or `draft13` (`c_nonce` in the
 * token answer, `proof`, `credential`); `cnfForm` is `jwk` or `kid`;
 * `serverMetadata: false` serves no authorization server metadata.
 */
export async function startIssuer(options = {}) {
	const { shape = 'final', cnfForm = 'kid', serverMetadata = true, profiles = {} } = options;
	const state = { offers: new Map(), tokens: new Map(), nonces: new Set(), requests: [], issued: [] };
	const service = await listen(async (req, res) => {
		const url = new URL(req.url, 'http://issuer.test');
		const issuer = `${service.url}/openid4vci`;
		state.requests.push(`${req.method} ${url.pathname}`);

		if (req.method === 'POST' && url.pathname === '/issuer2/credential-offers') {
			const body = JSON.parse(await readBody(req));
			const profile = profiles[body.profileId];
			if (!profile) {
				return send(res, 404, { error: 'unknown profile' });
			}
			const id = b64url(randomBytes(8));
			const code = b64url(randomBytes(16));
			const claims = { ...profile.credentialData, ...(body.runtimeOverrides?.credentialData ?? {}) };
			state.offers.set(id, { profileId: body.profileId, code, claims, sd: profile.sd ?? [] });
			return send(res, 201, { offerId: id, profileId: body.profileId, authMethod: body.authMethod, credentialOffer: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${issuer}/credential-offer?id=${id}`)}` });
		}
		if (req.method === 'GET' && url.pathname === '/openid4vci/credential-offer') {
			const offer = state.offers.get(url.searchParams.get('id'));
			if (!offer) {
				return send(res, 404, { error: 'unknown offer' });
			}
			return send(res, 200, { credential_issuer: issuer, credential_configuration_ids: [offer.profileId], grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': offer.code } } });
		}
		if (req.method === 'GET' && url.pathname === '/.well-known/openid-credential-issuer/openid4vci') {
			const configurations = {};
			for (const [id, profile] of Object.entries(profiles)) {
				configurations[id] = { format: 'dc+sd-jwt', vct: profile.vct, scope: id, cryptographic_binding_methods_supported: ['jwk', 'did:jwk'], credential_signing_alg_values_supported: ['ES256'], proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } } };
			}
			const metadata = { credential_issuer: issuer, credential_endpoint: `${issuer}/credential`, credential_configurations_supported: configurations };
			if (shape === 'final') {
				metadata.nonce_endpoint = `${issuer}/nonce`;
			}
			return send(res, 200, metadata);
		}
		if (req.method === 'GET' && url.pathname === '/.well-known/oauth-authorization-server/openid4vci') {
			if (!serverMetadata) {
				return send(res, 404, { error: 'not here' });
			}
			return send(res, 200, { issuer, token_endpoint: `${issuer}/token`, grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'] });
		}
		if (req.method === 'POST' && url.pathname === '/openid4vci/token') {
			const form = new URLSearchParams(await readBody(req));
			const offer = [...state.offers.values()].find((o) => o.code === form.get('pre-authorized_code'));
			if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code' || !offer) {
				return send(res, 400, { error: 'invalid_grant' });
			}
			const access = b64url(randomBytes(16));
			state.tokens.set(access, offer);
			const answer = { access_token: access, token_type: 'bearer', expires_in: 300 };
			if (shape === 'draft13') {
				const nonce = b64url(randomBytes(12));
				state.nonces.add(nonce);
				answer.c_nonce = nonce;
				answer.c_nonce_expires_in = 300;
			}
			return send(res, 200, answer);
		}
		if (req.method === 'POST' && url.pathname === '/openid4vci/nonce') {
			const nonce = b64url(randomBytes(12));
			state.nonces.add(nonce);
			return send(res, 200, { c_nonce: nonce });
		}
		if (req.method === 'POST' && url.pathname === '/openid4vci/credential') {
			const access = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
			const offer = state.tokens.get(access);
			if (!offer) {
				return send(res, 401, { error: 'invalid_token' });
			}
			const body = JSON.parse(await readBody(req));
			let proof;
			if (shape === 'final') {
				if (body.credential_configuration_id !== offer.profileId || !Array.isArray(body.proofs?.jwt)) {
					return send(res, 400, { error: 'invalid_credential_request', error_description: 'expected credential_configuration_id and proofs.jwt' });
				}
				proof = body.proofs.jwt[0];
			} else {
				if (body.proof?.proof_type !== 'jwt' || body.format !== 'dc+sd-jwt') {
					return send(res, 400, { error: 'invalid_credential_request', error_description: 'expected format and proof' });
				}
				proof = body.proof.jwt;
			}
			const decoded = decodeJwt(proof);
			if (decoded.header.typ !== 'openid4vci-proof+jwt' || decoded.payload.aud !== issuer || !state.nonces.has(decoded.payload.nonce)) {
				return send(res, 400, { error: 'invalid_proof', error_description: 'typ, aud or nonce' });
			}
			const holderJwk = decoded.header.jwk ?? holderKeyOf({ kid: decoded.header.kid });
			if (!verifyJwt(proof, holderJwk)) {
				return send(res, 400, { error: 'invalid_proof', error_description: 'signature' });
			}
			state.nonces.delete(decoded.payload.nonce);
			const cnf = cnfForm === 'jwk' ? { jwk: publicJwk(holderJwk) } : { kid: decoded.header.kid ?? didJwkKeyId(holderJwk) };
			const credential = issueSdJwt({ claims: offer.claims, sd: offer.sd, holder: cnf, vct: profiles[offer.profileId].vct });
			state.issued.push({ profileId: offer.profileId, cnf, claims: offer.claims });
			return send(res, 200, shape === 'final' ? { credentials: [{ credential }] } : { credential });
		}
		return send(res, 404, { error: 'not_found', path: url.pathname });
	});
	return { ...service, state, issuer: `${service.url}/openid4vci` };
}

/** A self-signed P-256 certificate for `host`, through openssl; null when openssl is missing. */
export function selfSigned(host) {
	const dir = mkdtempSync(join(tmpdir(), 'agent-cert-'));
	const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`, '-days', '1'], { encoding: 'utf8' });
	if (result.status !== 0) {
		rmSync(dir, { recursive: true, force: true });
		return null;
	}
	const keyPem = readFileSync(join(dir, 'key.pem'), 'utf8');
	const certPem = readFileSync(join(dir, 'cert.pem'), 'utf8');
	rmSync(dir, { recursive: true, force: true });
	const der = Buffer.from(certPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
	return { key: createPrivateKey(keyPem).export({ format: 'jwk' }), x5c: [der.toString('base64')], der, publicKey: createPublicKey(certPem) };
}

/**
 * The verifier. `signed` takes what selfSigned() returns, with `clientId`
 * (e.g. `x509_san_dns:verifier.test`); unsigned sessions use a `redirect_uri:`
 * client id, as walt.id does without a configured identity.
 */
export async function startVerifier(options = {}) {
	const { signed = null, clientId = null, responseMode = 'direct_post', dcql = null, responseUriHost = null } = options;
	const state = { sessions: new Map() };
	const service = await listen(async (req, res) => {
		const url = new URL(req.url, 'http://verifier.test');
		const match = /^\/verification-session\/([^/]+)\/(request|response)$/.exec(url.pathname);
		if (!match) {
			return send(res, 404, { error: 'not_found' });
		}
		const session = state.sessions.get(match[1]);
		if (!session) {
			return send(res, 404, { error: 'unknown session' });
		}
		if (match[2] === 'request' && req.method === 'GET') {
			if (signed === null) {
				return send(res, 200, session.request);
			}
			const jws = signJwt({ typ: 'oauth-authz-req+jwt', x5c: signed.x5c }, session.request, signed.key);
			return send(res, 200, jws, 'application/oauth-authz-req+jwt');
		}
		if (match[2] === 'response' && req.method === 'POST') {
			if (!(req.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded')) {
				return send(res, 400, { error: 'invalid_request', error_description: 'form expected' });
			}
			const form = new URLSearchParams(await readBody(req));
			if (form.get('state') !== session.request.state) {
				return send(res, 400, { error: 'invalid_request', error_description: 'state' });
			}
			let token;
			try {
				token = JSON.parse(form.get('vp_token') ?? '');
			} catch {
				return send(res, 400, { error: 'invalid_request', error_description: 'vp_token is not JSON' });
			}
			const queryId = session.request.dcql_query.credentials[0].id;
			const value = token[queryId];
			const presentation = Array.isArray(value) ? value[0] : value;
			if (typeof presentation !== 'string') {
				return send(res, 400, { error: 'invalid_request', error_description: `no presentation for ${queryId}` });
			}
			try {
				session.received = { ...verifyPresentation(presentation, { clientId: session.request.client_id, nonce: session.request.nonce }), form: Array.isArray(value) ? 'array' : 'string', vpToken: token };
			} catch (error) {
				session.rejected = error.message;
				return send(res, 400, { error: 'invalid_presentation', error_description: error.message });
			}
			return send(res, 200, { status: 'received', message: 'Presentation received and is being processed.' });
		}
		return send(res, 405, { error: 'method' });
	});
	const defaultDcql = {
		credentials: [{ id: 'agent', format: 'dc+sd-jwt', meta: { vct_values: [AGENT_VCT] }, claims: [{ path: ['acts_for'] }, { path: ['scope'] }, { path: ['agent', 'name'] }, { path: ['agent', 'operator'] }] }],
	};
	function createSession(overrides = {}) {
		const id = b64url(randomBytes(8));
		const host = responseUriHost ?? new URL(service.url).host;
		const responseUri = `http://${host}/verification-session/${id}/response`;
		const request = {
			response_type: 'vp_token',
			response_mode: responseMode,
			client_id: clientId ?? `redirect_uri:${responseUri}`,
			response_uri: responseUri,
			nonce: b64url(randomBytes(16)),
			state: b64url(randomBytes(8)),
			dcql_query: dcql ?? defaultDcql,
			client_metadata: { client_name: 'blocLabs' },
			...overrides,
		};
		state.sessions.set(id, { request, received: null, rejected: null });
		return { id, walletUrl: `openid4vp://authorize?client_id=${encodeURIComponent(request.client_id)}&request_uri=${encodeURIComponent(`${service.url}/verification-session/${id}/request`)}` };
	}
	return { ...service, state, createSession };
}

/**
 * WordPress with the agent routes (ADR 0007 §2). `pendingPolls` is how many
 * 409 answers follow the verifier's acceptance before the token (the chain's
 * delay). `agentLoginOff` answers 404 to every agent route.
 */
export async function startWordPress(verifier, options = {}) {
	const { pendingPolls = 1, agentLoginOff = false, scopes = ['read', 'content'] } = options;
	const state = { attempts: new Map(), tokens: new Map(), calls: [] };
	const service = await listen(async (req, res) => {
		const url = new URL(req.url, 'http://wordpress.test');
		state.calls.push({ method: req.method, path: url.pathname, authorization: req.headers.authorization ?? null, attemptHeader: req.headers['x-bloclabs-ssi-attempt'] ?? null });
		const wpError = (status, code, message, extra = {}) => send(res, status, { code, message, data: { status, ...extra } });

		if (url.pathname.startsWith('/wp-json/bloclabs-ssi/v1/agent/') && agentLoginOff) {
			return wpError(404, 'rest_no_route', 'No route was found matching the URL and request method.');
		}
		if (req.method === 'POST' && url.pathname === '/wp-json/bloclabs-ssi/v1/agent/initiate') {
			const body = JSON.parse((await readBody(req)) || '{}');
			const requested = Array.isArray(body.scope) && body.scope.length > 0 ? body.scope : ['read'];
			const session = verifier.createSession();
			const id = b64url(randomBytes(16));
			const secret = b64url(randomBytes(32));
			state.attempts.set(id, { secret, session: session.id, requested, polls: 0, status: 'pending' });
			return send(res, 201, { attempt: id, attempt_secret: secret, wallet_url: session.walletUrl, expires_in: 180, poll_after: 0.01 });
		}
		if (req.method === 'POST' && url.pathname === '/wp-json/bloclabs-ssi/v1/agent/token') {
			const body = JSON.parse((await readBody(req)) || '{}');
			const attempt = state.attempts.get(body.attempt);
			if (!attempt || attempt.secret !== req.headers['x-bloclabs-ssi-attempt']) {
				return wpError(404, 'bloclabs_ssi_unknown_attempt', 'Unknown login request.');
			}
			if (attempt.status === 'consumed') {
				return wpError(409, 'bloclabs_ssi_already_used', 'This login request was already used.');
			}
			const session = verifier.state.sessions.get(attempt.session);
			if (!session.received || attempt.polls < pendingPolls) {
				attempt.polls += 1;
				return wpError(409, 'bloclabs_ssi_pending', 'Not verified yet.', { poll_after: 0.01 });
			}
			attempt.status = 'consumed';
			const token = `bssi_${b64url(randomBytes(32))}`;
			const credentialScope = Array.isArray(session.received.claims.scope) ? session.received.claims.scope : null;
			const scope = attempt.requested.filter((s) => scopes.includes(s) && (credentialScope === null || credentialScope.includes(s)));
			const record = { token, user_id: 7, delegated: typeof session.received.claims.acts_for === 'string' && session.received.claims.acts_for !== '', scope, expires_at: new Date(Date.now() + 3600_000).toISOString() };
			state.tokens.set(token, record);
			return send(res, 200, { token, token_type: 'Bearer', expires_at: record.expires_at, scope, user_id: record.user_id, delegated: record.delegated });
		}
		const bearer = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
		const record = state.tokens.get(bearer);
		if (req.method === 'DELETE' && url.pathname === '/wp-json/bloclabs-ssi/v1/agent/token') {
			if (!record) {
				return wpError(401, 'bloclabs_ssi_token_refused', 'The application token was not accepted.');
			}
			state.tokens.delete(bearer);
			return send(res, 200, { revoked: true });
		}
		if (url.pathname.startsWith('/wp-json/wp/v2/')) {
			if (!record) {
				return wpError(401, 'rest_not_logged_in', 'You are not currently logged in.');
			}
			if (url.pathname === '/wp-json/wp/v2/users/me') {
				return send(res, 200, { id: record.user_id, name: 'Demo', scope: record.scope });
			}
			if (url.pathname === '/wp-json/wp/v2/settings') {
				return wpError(403, 'rest_forbidden', 'Sorry, you are not allowed to do that.');
			}
			if (url.pathname === '/wp-json/wp/v2/posts' && req.method === 'POST') {
				return record.scope.includes('content') ? send(res, 201, { id: 42, status: 'draft' }) : wpError(403, 'rest_cannot_create', 'Sorry, you are not allowed to create posts as this user.');
			}
		}
		return wpError(404, 'rest_no_route', 'No route was found matching the URL and request method.');
	});
	return { ...service, state };
}

export const AGENT_PROFILE = {
	vct: AGENT_VCT,
	sd: ['acts_for', 'scope', 'agent'],
	credentialData: { acts_for: '', scope: ['read', 'content'], agent: { name: 'Nightly backup', operator: 'blocLabs demo' } },
};

export { thumbprintUri };
