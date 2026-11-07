import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { test } from 'node:test';

import { b64url, b64urlDecode, decodeJwt, didJwk, didJwkKeyId, generateKey, publicJwk, signJwt, thumbprint, thumbprintUri, verifyJwt } from '../lib/jose.mjs';

test('the RFC 7638 thumbprint uses the required EC members in order and nothing else', () => {
	// RFC 7517 appendix A.1 key; the thumbprint is the one the bridge's tests pin for this key.
	const jwk = { kty: 'EC', crv: 'P-256', x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4', y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM', use: 'enc', kid: '1' };
	assert.equal(thumbprint(jwk), thumbprint({ ...jwk, d: 'ignored', alg: 'ES256' }), 'private and optional members do not change it');
	assert.match(thumbprint(jwk), /^[A-Za-z0-9_-]{43}$/);
	assert.equal(thumbprintUri(jwk), `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${thumbprint(jwk)}`);
	assert.throws(() => thumbprint({ kty: 'RSA', n: 'x', e: 'AQAB' }), /only EC keys/);
});

test('did:jwk encodes the public key only and its key id is fragment 0', () => {
	const key = generateKey();
	const did = didJwk(key);
	assert.match(did, /^did:jwk:[A-Za-z0-9_-]+$/);
	assert.deepEqual(JSON.parse(b64urlDecode(did.slice('did:jwk:'.length)).toString()), publicJwk(key));
	assert.equal(didJwkKeyId(key), `${did}#0`);
	assert.equal('d' in publicJwk(key), false);
});

test('ES256 compact JWS signs with a raw signature and verifies with the JWK or a KeyObject', () => {
	const key = generateKey();
	const jws = signJwt({ typ: 'kb+jwt' }, { nonce: 'n', aud: 'a' }, key);
	const { header, payload, signature } = decodeJwt(jws);
	assert.deepEqual(header, { typ: 'kb+jwt', alg: 'ES256' });
	assert.deepEqual(payload, { nonce: 'n', aud: 'a' });
	assert.equal(b64urlDecode(signature).length, 64, 'r||s, not DER');
	assert.equal(verifyJwt(jws, publicJwk(key)), true);
	assert.equal(verifyJwt(jws, createPublicKey({ key: publicJwk(key), format: 'jwk' })), true);
	assert.equal(verifyJwt(jws, publicJwk(generateKey())), false);
	const tampered = `${jws.split('.')[0]}.${b64url(JSON.stringify({ nonce: 'x', aud: 'a' }))}.${signature}`;
	assert.equal(verifyJwt(tampered, publicJwk(key)), false);
	assert.throws(() => verifyJwt(`${b64url('{"alg":"HS256"}')}.e30.sig`, publicJwk(key)), /ES256/);
	assert.throws(() => decodeJwt('a.b'), /compact JWS/);
});
