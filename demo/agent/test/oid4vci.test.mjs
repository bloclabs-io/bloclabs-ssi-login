import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { decodeJwt, didJwk, didJwkKeyId, generateKey, publicJwk, thumbprintUri } from '../lib/jose.mjs';
import { receive, resolveOffer, wellKnownCandidates } from '../lib/oid4vci.mjs';
import { holderSubjectId, parse, resolve } from '../lib/sdjwt.mjs';
import { ACTS_FOR, AGENT_PROFILE, AGENT_VCT, startIssuer } from './support.mjs';

const key = generateKey();
const quiet = () => {};

async function offerFrom(issuer, overrides) {
	const response = await fetch(`${issuer.url}/issuer2/credential-offers`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ profileId: 'agent', authMethod: 'PRE_AUTHORIZED', expiresInSeconds: 600, ...(overrides ? { runtimeOverrides: { credentialData: overrides } } : {}) }),
	});
	return (await response.json()).credentialOffer;
}

test('well-known URLs put the suffix between host and path, then try the plain form', () => {
	assert.deepEqual(wellKnownCandidates('http://issuer.demo/openid4vci', 'openid-credential-issuer'), [
		'http://issuer.demo/.well-known/openid-credential-issuer/openid4vci',
		'http://issuer.demo/openid4vci/.well-known/openid-credential-issuer',
	]);
	assert.deepEqual(wellKnownCandidates('https://issuer.example.com/', 'oauth-authorization-server'), ['https://issuer.example.com/.well-known/oauth-authorization-server']);
});

test('offers are read by reference, by value, as a bare URL and as JSON', async () => {
	const offer = { credential_issuer: 'https://issuer.example.com/openid4vci', credential_configuration_ids: ['agent'], grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'code-1' } } };
	const fetchImpl = async (url) => new Response(JSON.stringify(offer), { headers: { 'content-type': 'application/json' } });
	const expected = { issuer: 'https://issuer.example.com/openid4vci', configurationIds: ['agent'], preAuthorizedCode: 'code-1', txCode: null, authorizationServer: null };
	assert.deepEqual(await resolveOffer(`openid-credential-offer://?credential_offer_uri=${encodeURIComponent('https://issuer.example.com/openid4vci/credential-offer?id=1')}`, { fetchImpl }), expected);
	assert.deepEqual(await resolveOffer(`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`), expected);
	assert.deepEqual(await resolveOffer('https://issuer.example.com/openid4vci/credential-offer?id=1', { fetchImpl }), expected);
	assert.deepEqual(await resolveOffer(JSON.stringify(offer)), expected);
	await assert.rejects(resolveOffer('openid-credential-offer://?nothing=1'), /neither credential_offer_uri nor credential_offer/);
	await assert.rejects(resolveOffer(JSON.stringify({ ...offer, grants: { authorization_code: {} } })), /no pre-authorized code/);
	await assert.rejects(resolveOffer(JSON.stringify({ ...offer, credential_configuration_ids: [] })), /credential_configuration_ids/);
	await assert.rejects(resolveOffer('mailto:x'), /unsupported credential offer scheme/);
});

for (const [shape, cnfForm, serverMetadata] of [['final', 'kid', true], ['draft13', 'jwk', false]]) {
	test(`receives an agent credential from a ${shape} issuer (cnf as ${cnfForm}, server metadata ${serverMetadata ? 'published' : 'absent'})`, async () => {
		const issuer = await startIssuer({ shape, cnfForm, serverMetadata, profiles: { agent: AGENT_PROFILE } });
		try {
			const offer = await offerFrom(issuer, { acts_for: ACTS_FOR });
			const log = [];
			const got = await receive(offer, key, { log: (line) => log.push(line) });

			assert.equal(got.issuer, issuer.issuer);
			assert.equal(got.configurationId, 'agent');
			assert.equal(got.vct, AGENT_VCT);
			const sdJwt = parse(got.credential);
			const { claims } = resolve(sdJwt);
			assert.equal(claims.acts_for, ACTS_FOR, 'the per-offer override reached the credential');
			assert.deepEqual(claims.scope, ['read', 'content']);
			assert.deepEqual(claims.agent, { name: 'Nightly backup', operator: 'blocLabs demo' });
			assert.equal(claims.vct, AGENT_VCT);
			assert.equal(holderSubjectId(sdJwt.payload.cnf), cnfForm === 'jwk' ? thumbprintUri(key) : didJwk(key), 'the credential is bound to the agent\'s key');

			assert.equal(issuer.state.issued.length, 1);
			const requests = issuer.state.requests;
			assert.ok(requests.includes('GET /.well-known/openid-credential-issuer/openid4vci'), 'metadata between host and path');
			assert.ok(requests.includes('POST /openid4vci/token'));
			assert.equal(requests.includes('POST /openid4vci/nonce'), shape === 'final', 'the nonce endpoint is used when published');
			assert.equal(requests.filter((r) => r === 'POST /openid4vci/credential').length, shape === 'final' ? 1 : 2, 'the draft shape is a fallback after a 400');
			if (shape === 'draft13') {
				assert.ok(log.some((line) => line.includes('draft 13')));
			}
		} finally {
			await issuer.close();
		}
	});
}

test('the proof of possession is what the issuer checks: typ, aud, nonce and the key', async () => {
	const issuer = await startIssuer({ profiles: { agent: AGENT_PROFILE } });
	try {
		const seen = [];
		const fetchImpl = async (url, init) => {
			if (String(url).endsWith('/openid4vci/credential')) {
				seen.push(JSON.parse(init.body));
			}
			return fetch(url, init);
		};
		await receive(await offerFrom(issuer), key, { fetchImpl, log: quiet, proofKey: 'jwk' });
		const proof = decodeJwt(seen[0].proofs.jwt[0]);
		assert.equal(proof.header.typ, 'openid4vci-proof+jwt');
		assert.deepEqual(proof.header.jwk, publicJwk(key), '--proof-key jwk puts the public key in the header');
		assert.equal('kid' in proof.header, false);
		assert.equal(proof.payload.aud, issuer.issuer);
		assert.equal(typeof proof.payload.nonce, 'string');
		assert.equal(typeof proof.payload.iat, 'number');

		seen.length = 0;
		await receive(await offerFrom(issuer), key, { fetchImpl, log: quiet });
		assert.equal(decodeJwt(seen[0].proofs.jwt[0]).header.kid, didJwkKeyId(key), 'the default names the key by did:jwk');
	} finally {
		await issuer.close();
	}
});

test('a refused code, a missing tx_code and a deferred credential are reported, not retried forever', async () => {
	const issuer = await startIssuer({ profiles: { agent: AGENT_PROFILE } });
	try {
		const offer = await offerFrom(issuer);
		const forged = offer.replace(/id(=|%3D)[^&]+/, 'id$1unknown');
		await assert.rejects(receive(forged, key, { log: quiet }), /HTTP 404/);

		const withTx = JSON.stringify({ credential_issuer: issuer.issuer, credential_configuration_ids: ['agent'], grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'x', tx_code: { input_mode: 'numeric', length: 4 } } } });
		await assert.rejects(receive(withTx, key, { log: quiet }), /tx_code/);

		const deferring = async (url, init) => {
			if (String(url).endsWith('/openid4vci/credential')) {
				return new Response(JSON.stringify({ transaction_id: 'later' }), { status: 202, headers: { 'content-type': 'application/json' } });
			}
			return fetch(url, init);
		};
		await assert.rejects(receive(await offerFrom(issuer), key, { log: quiet, fetchImpl: deferring }), /deferred/);
	} finally {
		await issuer.close();
	}
});
