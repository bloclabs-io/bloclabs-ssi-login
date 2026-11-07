import test from 'node:test';
import assert from 'node:assert/strict';

import { certificateHash, generateKey, didJwkKeyId, publicJwk } from '../lib/jose.mjs';
import { checkVerifier, chooseCredentialQuery, fetchRequest, parseWalletUrl, respond, vpToken } from '../lib/oid4vp.mjs';
import { parse, present, select } from '../lib/sdjwt.mjs';
import { ACTS_FOR, AGENT_PROFILE, AGENT_VCT, issueSdJwt, selfSigned, startVerifier } from './support.mjs';

const key = generateKey();
const credential = issueSdJwt({
	claims: { ...AGENT_PROFILE.credentialData, acts_for: ACTS_FOR },
	sd: AGENT_PROFILE.sd,
	holder: { kid: didJwkKeyId(key) },
});

test('wallet URLs: the schemes wallets register, and what they carry', () => {
	const parsed = parseWalletUrl('openid4vp://authorize?client_id=redirect_uri%3Ahttp%3A%2F%2Fv%2Fr&request_uri=http%3A%2F%2Fv%2Freq');
	assert.deepEqual(parsed, { clientId: 'redirect_uri:http://v/r', requestUri: 'http://v/req', request: null });
	assert.equal(parseWalletUrl('haip://authorize?request_uri=http%3A%2F%2Fv%2Freq').requestUri, 'http://v/req');
	assert.equal(parseWalletUrl('https://wallet.example/authorize?request=eyJ').request, 'eyJ');
	assert.throws(() => parseWalletUrl('javascript:alert(1)'), /unsupported wallet URL scheme/);
	assert.throws(() => parseWalletUrl('not a url'), /does not parse/);
});

test('an unsigned request with a redirect_uri client id is accepted when the id names the response_uri', async () => {
	const verifier = await startVerifier();
	try {
		const { walletUrl } = verifier.createSession();
		const { request, leaf, clientId } = await fetchRequest(walletUrl);
		assert.equal(leaf, null);
		const checked = checkVerifier(request, { clientId, leaf });
		assert.equal(checked.clientId, request.client_id);
		assert.equal(checked.responseUri, request.response_uri);
		assert.equal(checked.nonce, request.nonce);
		assert.equal(checked.state, request.state);
	} finally {
		await verifier.close();
	}
});

test('the request must name the verifier the wallet URL named, and the pinned one', async () => {
	const verifier = await startVerifier();
	try {
		const { walletUrl } = verifier.createSession();
		const { request, leaf } = await fetchRequest(walletUrl);
		assert.throws(() => checkVerifier(request, { clientId: 'redirect_uri:http://evil.test/r', leaf }), /another verifier than the wallet URL/);
		assert.throws(() => checkVerifier(request, { clientId: request.client_id, leaf, expected: 'x509_san_dns:verifier.example' }), /not the pinned/);
		assert.equal(checkVerifier(request, { clientId: request.client_id, leaf, expected: request.client_id }).clientId, request.client_id);
		assert.equal(checkVerifier(request, { clientId: null, leaf }).clientId, request.client_id, 'a wallet URL without client_id leaves the request to name it');
	} finally {
		await verifier.close();
	}
});

test('a redirect_uri client id that names another response_uri is a relay, not a verifier', async () => {
	const verifier = await startVerifier();
	try {
		const { walletUrl } = verifier.createSession({ client_id: 'redirect_uri:http://evil.test/collect' });
		const { request, leaf, clientId } = await fetchRequest(walletUrl);
		assert.throws(() => checkVerifier(request, { clientId, leaf }), /must name the response_uri/);
	} finally {
		await verifier.close();
	}
});

test('only vp_token by direct_post in clear is answered', async () => {
	const encrypted = await startVerifier({ responseMode: 'direct_post.jwt' });
	try {
		const { walletUrl } = encrypted.createSession();
		const { request, leaf, clientId } = await fetchRequest(walletUrl);
		assert.throws(() => checkVerifier(request, { clientId, leaf }), /direct_post\.jwt is not supported/);
		assert.throws(() => checkVerifier({ ...request, response_mode: 'direct_post', response_type: 'id_token' }, { clientId, leaf }), /does not ask for a vp_token/);
		assert.throws(() => checkVerifier({ ...request, response_mode: 'direct_post', nonce: '' }, { clientId, leaf }), /no nonce/);
		assert.throws(() => checkVerifier({ ...request, response_mode: 'direct_post', response_uri: 'ftp://x' }, { clientId, leaf }), /response_uri/);
	} finally {
		await encrypted.close();
	}
});

test('client id schemes this agent cannot check are refused rather than trusted', async () => {
	const verifier = await startVerifier({ clientId: 'did:web:verifier.test' });
	try {
		const { walletUrl } = verifier.createSession();
		const { request, leaf, clientId } = await fetchRequest(walletUrl);
		assert.throws(() => checkVerifier(request, { clientId, leaf }), /client id scheme did is not one this agent can check/);
		assert.throws(() => checkVerifier({ ...request, client_id: 'x509_san_dns:verifier.test' }, { clientId: 'x509_san_dns:verifier.test', leaf: null }), /needs a signed request/);
	} finally {
		await verifier.close();
	}
});

const cert = selfSigned('verifier.test');

test('a signed request is verified under its x5c leaf, which must be issued to the x509_san_dns name', { skip: cert === null && 'openssl is not installed' }, async () => {
	const verifier = await startVerifier({ signed: cert, clientId: 'x509_san_dns:verifier.test', responseUriHost: 'verifier.test' });
	try {
		const { walletUrl } = verifier.createSession();
		const fetched = await fetchRequest(walletUrl);
		assert.notEqual(fetched.leaf, null, 'the leaf certificate came out of x5c');
		const checked = checkVerifier(fetched.request, { clientId: fetched.clientId, leaf: fetched.leaf });
		assert.equal(checked.clientId, 'x509_san_dns:verifier.test');
		assert.equal(new URL(checked.responseUri).hostname, 'verifier.test');

		assert.throws(() => checkVerifier({ ...fetched.request, client_id: 'x509_san_dns:other.test' }, { clientId: 'x509_san_dns:other.test', leaf: fetched.leaf }), /not issued to other.test/);
		assert.throws(() => checkVerifier({ ...fetched.request, response_uri: 'http://attacker.test/collect' }, { clientId: fetched.clientId, leaf: fetched.leaf }), /response_uri is on attacker.test/);

		const byHash = `x509_hash:${certificateHash(fetched.leaf)}`;
		assert.equal(checkVerifier({ ...fetched.request, client_id: byHash }, { clientId: byHash, leaf: fetched.leaf }).clientId, byHash);
		assert.throws(() => checkVerifier({ ...fetched.request, client_id: 'x509_hash:nope' }, { clientId: 'x509_hash:nope', leaf: fetched.leaf }), /not the one the client id names/);
	} finally {
		await verifier.close();
	}
});

test('a signed request whose signature does not match its x5c leaf is refused', { skip: cert === null && 'openssl is not installed' }, async () => {
	const other = selfSigned('verifier.test');
	const verifier = await startVerifier({ signed: { ...cert, key: other.key }, clientId: 'x509_san_dns:verifier.test' });
	try {
		const { walletUrl } = verifier.createSession();
		await assert.rejects(fetchRequest(walletUrl), /does not verify under its x5c leaf/);
	} finally {
		await verifier.close();
	}
});

test('the DCQL query picked is the SD-JWT VC one whose vct_values name the credential', () => {
	const dcql = {
		credentials: [
			{ id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' } },
			{ id: 'member', format: 'dc+sd-jwt', meta: { vct_values: ['http://issuer.test/openid4vci/member'] }, claims: [{ path: ['email'] }] },
			{ id: 'agent', format: 'dc+sd-jwt', meta: { vct_values: [AGENT_VCT] }, claims: [{ path: ['acts_for'] }, { path: ['agent', 'name'] }] },
		],
	};
	assert.deepEqual(chooseCredentialQuery(dcql, AGENT_VCT), { id: 'agent', paths: [['acts_for'], ['agent', 'name']] });
	assert.deepEqual(chooseCredentialQuery({ credentials: [{ id: 'any', format: 'vc+sd-jwt' }] }, AGENT_VCT), { id: 'any', paths: undefined }, 'no vct_values and no claims: every disclosure');
	assert.throws(() => chooseCredentialQuery(dcql, 'http://issuer.test/openid4vci/other'), /asks for no SD-JWT VC credential this agent holds/);
	assert.throws(() => chooseCredentialQuery({ credentials: [{ id: 'bad', format: 'dc+sd-jwt', claims: [{ nope: true }] }] }, AGENT_VCT), /DCQL claim has no path/);
});

test('the presentation posted by direct_post carries the KB-JWT the verifier checks, in both vp_token forms', async () => {
	const verifier = await startVerifier();
	try {
		for (const form of ['array', 'string']) {
			const session = verifier.createSession();
			const { request, leaf, clientId } = await fetchRequest(session.walletUrl);
			const checked = checkVerifier(request, { clientId, leaf });
			const sdJwt = parse(credential);
			const query = chooseCredentialQuery(request.dcql_query, AGENT_VCT);
			const disclosures = select(sdJwt, query.paths);
			const presentation = present(sdJwt, disclosures, { aud: checked.clientId, nonce: checked.nonce }, key);
			const answer = await respond(checked.responseUri, vpToken(query.id, presentation, form), checked.state);
			assert.equal(answer.status, 'received');
			const received = verifier.state.sessions.get(session.id).received;
			assert.equal(received.form, form);
			assert.equal(received.claims.acts_for, ACTS_FOR);
			assert.deepEqual(received.claims.agent, { name: 'Nightly backup', operator: 'blocLabs demo' });
			assert.deepEqual(received.disclosed.sort(), ['acts_for', 'agent', 'scope'], 'the requested claims and nothing beyond them');
			assert.equal(received.kb.aud, checked.clientId);
		}
	} finally {
		await verifier.close();
	}
});

test('a presentation bound to another verifier or nonce is refused by the verifier, and the agent reports that', async () => {
	const verifier = await startVerifier();
	try {
		const session = verifier.createSession();
		const { request, leaf, clientId } = await fetchRequest(session.walletUrl);
		const checked = checkVerifier(request, { clientId, leaf });
		const sdJwt = parse(credential);
		const disclosures = select(sdJwt, undefined);
		const wrongNonce = present(sdJwt, disclosures, { aud: checked.clientId, nonce: 'stale' }, key);
		await assert.rejects(respond(checked.responseUri, vpToken('agent', wrongNonce), checked.state), /refused the presentation: HTTP 400 \(invalid_presentation: kb nonce\)/);
		assert.equal(verifier.state.sessions.get(session.id).received, null);

		const otherKey = generateKey();
		const stolen = present(sdJwt, disclosures, { aud: checked.clientId, nonce: checked.nonce }, otherKey);
		await assert.rejects(respond(checked.responseUri, vpToken('agent', stolen), checked.state), /kb signature/);
		assert.equal(publicJwk(otherKey).kty, 'EC');
	} finally {
		await verifier.close();
	}
});
