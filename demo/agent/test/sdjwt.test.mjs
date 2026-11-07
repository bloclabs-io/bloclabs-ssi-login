import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { b64url, decodeJwt, didJwkKeyId, generateKey, publicJwk, thumbprintUri, verifyJwt } from '../lib/jose.mjs';
import { decodeDisclosure, digest, holderSubjectId, parse, present, resolve, sdHashInput, select } from '../lib/sdjwt.mjs';
import { ACTS_FOR, AGENT_VCT, issueSdJwt, verifyPresentation } from './support.mjs';

const holder = generateKey();

function agentCredential(options = {}) {
	return issueSdJwt({
		claims: { acts_for: ACTS_FOR, scope: ['read', 'content'], agent: { name: 'Nightly backup', operator: 'blocLabs demo' }, plain: 'visible' },
		sd: ['acts_for', 'scope', 'agent'],
		holder: { kid: didJwkKeyId(holder) },
		...options,
	});
}

test('an issued SD-JWT parses into the issuer JWT, its disclosures and no KB-JWT', () => {
	const sdJwt = parse(agentCredential());
	assert.equal(sdJwt.kbJwt, null);
	assert.equal(sdJwt.disclosures.length, 3);
	assert.equal(sdJwt.alg, 'sha-256');
	assert.equal(sdJwt.header.typ, 'dc+sd-jwt');
	assert.equal(sdJwt.payload.vct, AGENT_VCT);
	assert.equal(sdJwt.payload.plain, 'visible');
	assert.equal('acts_for' in sdJwt.payload, false, 'selectively disclosable claims are digests in the payload');
	assert.equal(parse(agentCredential().replace(/~$/, '')).disclosures.length, 3, 'a missing trailing tilde is tolerated');
	assert.throws(() => parse(agentCredential({ alg: 'md5' })), /unsupported _sd_alg/);
});

test('resolve applies every disclosure and remembers which disclosures each claim needs', () => {
	const sdJwt = parse(agentCredential());
	const { claims, needed } = resolve(sdJwt);
	assert.equal(claims.acts_for, ACTS_FOR);
	assert.deepEqual(claims.scope, ['read', 'content']);
	assert.deepEqual(claims.agent, { name: 'Nightly backup', operator: 'blocLabs demo' });
	assert.equal('_sd' in claims, false);
	assert.equal('_sd_alg' in claims, false);
	assert.equal(needed.get(JSON.stringify(['agent'])).length, 1);
	const d = needed.get(JSON.stringify(['scope']))[0];
	assert.equal(decodeDisclosure(d).name, 'scope');
	assert.equal(digest(d), sdJwt.payload._sd.find((x) => x === digest(d)));
});

test('select picks the disclosures behind the requested claim paths and nothing else', () => {
	const sdJwt = parse(agentCredential());
	const names = (ds) => ds.map((d) => decodeDisclosure(d).name).sort();
	assert.deepEqual(names(select(sdJwt, [['acts_for'], ['agent', 'name']])), ['acts_for', 'agent']);
	assert.deepEqual(names(select(sdJwt, [['plain']])), [], 'a plain claim needs no disclosure');
	assert.deepEqual(names(select(sdJwt, undefined)), ['acts_for', 'agent', 'scope'], 'no claims in the query: everything');
	assert.deepEqual(names(select(sdJwt, [['scope', null]])), ['scope'], 'null selects the array elements');
	assert.throws(() => select(sdJwt, [['email']]), /no claim at \["email"\]/);
	assert.throws(() => select(sdJwt, [[]]), /non-empty/);
});

test('a nested selectively disclosable member needs its own disclosure and its parent\'s', () => {
	const compact = issueSdJwt({
		claims: { agent: { name: 'Nightly backup', operator: 'blocLabs demo' }, acts_for: ACTS_FOR },
		sd: ['agent', 'acts_for'],
		nestedSd: { agent: ['name', 'operator'] },
		holder: { jwk: publicJwk(holder) },
	});
	const sdJwt = parse(compact);
	assert.equal(sdJwt.disclosures.length, 4);
	const chosen = select(sdJwt, [['agent', 'name']]);
	assert.deepEqual(chosen.map((d) => decodeDisclosure(d).name).sort(), ['agent', 'name']);
	const whole = select(sdJwt, [['agent']]);
	assert.deepEqual(whole.map((d) => decodeDisclosure(d).name).sort(), ['agent', 'name', 'operator'], 'asking for the object discloses what is inside it');
	assert.deepEqual(resolve(sdJwt).claims.agent, { name: 'Nightly backup', operator: 'blocLabs demo' });
});

test('present binds the chosen disclosures to the verifier with a KB-JWT the verifier accepts', () => {
	const sdJwt = parse(agentCredential());
	const disclosures = select(sdJwt, [['acts_for'], ['scope']]);
	const presentation = present(sdJwt, disclosures, { aud: 'redirect_uri:https://verifier.test/r', nonce: 'nonce-1', iat: 1_793_707_200 }, holder);

	const parts = presentation.split('~');
	assert.equal(parts[0], sdJwt.issuerJwt, 'the issuer JWT is untouched');
	assert.deepEqual(parts.slice(1, -1), disclosures);
	const kb = decodeJwt(parts.at(-1));
	assert.deepEqual(kb.header, { typ: 'kb+jwt', alg: 'ES256' });
	assert.equal(kb.payload.aud, 'redirect_uri:https://verifier.test/r');
	assert.equal(kb.payload.nonce, 'nonce-1');
	assert.equal(kb.payload.iat, 1_793_707_200);
	assert.equal(kb.payload.sd_hash, b64url(createHash('sha256').update(sdHashInput(sdJwt.issuerJwt, disclosures), 'ascii').digest()));
	assert.equal(verifyJwt(parts.at(-1), publicJwk(holder)), true);

	const checked = verifyPresentation(presentation, { clientId: 'redirect_uri:https://verifier.test/r', nonce: 'nonce-1' });
	assert.deepEqual(checked.disclosed.sort(), ['acts_for', 'scope']);
	assert.equal(checked.claims.acts_for, ACTS_FOR);
	assert.equal('agent' in checked.claims, false, 'what was not disclosed is not there');
	assert.throws(() => verifyPresentation(presentation, { clientId: 'redirect_uri:https://other.test/r', nonce: 'nonce-1' }), /aud/);
	assert.throws(() => verifyPresentation(presentation, { clientId: 'redirect_uri:https://verifier.test/r', nonce: 'other' }), /nonce/);
	assert.throws(() => present(sdJwt, disclosures, { aud: '', nonce: 'n' }, holder), /audience and nonce/);

	const reparsed = parse(presentation);
	assert.equal(reparsed.kbJwt, parts.at(-1));
	assert.deepEqual(reparsed.disclosures, disclosures);
	assert.equal(sdHashInput(sdJwt.issuerJwt, []), `${sdJwt.issuerJwt}~`, 'with no disclosure the hash covers the JWT and one tilde');
});

test('the subject id is derived as the bridge derives it', () => {
	assert.equal(holderSubjectId({ jwk: publicJwk(holder) }), thumbprintUri(holder));
	assert.equal(holderSubjectId({ kid: `${didJwkKeyId(holder)}` }), didJwkKeyId(holder).split('#')[0]);
	assert.equal(holderSubjectId({ kid: 'did:key:z6Mk#z6Mk' }), 'did:key:z6Mk');
	assert.equal(holderSubjectId({ kid: 'https://not-a-did' }), null);
	assert.equal(holderSubjectId({ kid: 'did:' }), null);
	assert.equal(holderSubjectId({ jwk: { kty: 'RSA' } }), null);
	assert.equal(holderSubjectId(null), null);
	assert.equal(holderSubjectId('x'), null);
});
