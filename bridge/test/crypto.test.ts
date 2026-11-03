import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { canonicalJson, constantTimeEqual, jwkThumbprint, jwkThumbprintUri, presentationHash, sha256Hex, subjectCommitment } from '../src/crypto.js';

describe('commitments', () => {
  it('matches the commitment the plugin checks, on the event captured from FireFly', () => {
    // The plugin's RealFireFlyEventTest checks the same fixture with its own PHP implementation.
    const fixture = JSON.parse(
      readFileSync(new URL('../../../tests/fixtures/firefly-login-attested.json', import.meta.url), 'utf8'),
    ) as { correlation: string; subject: string; commitment: string };
    assert.equal(subjectCommitment(fixture.correlation, fixture.subject), fixture.commitment);
    assert.equal(subjectCommitment(fixture.correlation.toUpperCase(), fixture.subject), fixture.commitment, 'case of the hex id does not matter');
  });

  it('hashes the vp_token map as canonical JSON', () => {
    const token = { pid: ['a~b~c'], mdl: ['xyz'] };
    assert.equal(canonicalJson(token), '{"mdl":["xyz"],"pid":["a~b~c"]}');
    assert.equal(presentationHash(token), sha256Hex('{"mdl":["xyz"],"pid":["a~b~c"]}'));
    assert.equal(presentationHash({ mdl: ['xyz'], pid: ['a~b~c'] }), presentationHash(token), 'key order does not matter');
  });

  it('canonical JSON drops undefined members and escapes strings like JSON', () => {
    assert.equal(canonicalJson({ b: 1, a: { d: [true, null, 'x"y'], c: undefined } }), '{"a":{"d":[true,null,"x\\"y"]},"b":1}');
    assert.throws(() => canonicalJson({ a: Number.NaN }));
  });
});

describe('JWK thumbprint', () => {
  it('reproduces the RFC 7638 example', () => {
    const jwk = {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
      kid: '2011-04-29',
    };
    assert.equal(jwkThumbprint(jwk), 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
    assert.equal(jwkThumbprintUri(jwk), 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('ignores members that are not part of the thumbprint and refuses incomplete keys', () => {
    const ec = { kty: 'EC', crv: 'P-256', x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4', y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM' };
    assert.equal(jwkThumbprint({ ...ec, kid: 'k1', use: 'sig' }), jwkThumbprint(ec));
    assert.throws(() => jwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'only' }), /missing the required member "y"/);
    assert.throws(() => jwkThumbprint({ kty: 'oct', k: 'secret' }), /Unsupported JWK key type/);
  });
});

describe('constant time comparison', () => {
  it('compares full strings', () => {
    assert.equal(constantTimeEqual('Bearer abc', 'Bearer abc'), true);
    assert.equal(constantTimeEqual('Bearer abc', 'Bearer abd'), false);
    assert.equal(constantTimeEqual('Bearer abc', 'Bearer ab'), false);
    assert.equal(constantTimeEqual('', ''), true);
  });
});
