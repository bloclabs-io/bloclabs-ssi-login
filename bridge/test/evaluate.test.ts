import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { presentationHash } from '../src/crypto.js';
import { buildSessionSetup, evaluateSession, holderSubjectId, resolveClaimPath, selectClaims } from '../src/verifier.js';
import { credentialData, failedSession, HOLDER_JWK, QUERIES, SD_JWT_PRESENTATION, successfulSession } from './helpers.js';

const query = QUERIES.default;

describe('session setup', () => {
  it('asks walt.id for a cross-device session with the configured query, expiry, retention and webhook', () => {
    const setup = buildSessionSetup({
      id: 'abc',
      query,
      expiresAt: new Date('2026-11-03T12:03:00Z'),
      retainUntil: new Date('2026-11-03T12:04:00Z'),
      webhookUrl: 'http://bridge:8090/v1/verifier-callbacks/abc',
      webhookToken: 'tok',
    });
    assert.deepEqual(setup, {
      flow_type: 'cross_device',
      core_flow: {
        sessionId: 'abc',
        dcql_query: query.dcql_query,
        expiration_date: '2026-11-03T12:03:00.000Z',
        retention_date: '2026-11-03T12:04:00.000Z',
        notifications: { webhook: { url: 'http://bridge:8090/v1/verifier-callbacks/abc', bearer_token: 'tok' } },
        policies: query.policies,
      },
    });
  });
});

describe('claim selection', () => {
  const data = credentialData({ nationalities: ['GB', 'FR'], degrees: [{ name: 'BSc' }, { name: 'MSc' }] });

  it('resolves OpenID4VP claim paths', () => {
    assert.equal(resolveClaimPath(data, ['given_name']), 'Ada');
    assert.equal(resolveClaimPath(data, ['address', 'locality']), 'London');
    assert.equal(resolveClaimPath(data, ['nationalities', 1]), 'FR');
    assert.deepEqual(resolveClaimPath(data, ['degrees', null, 'name']), ['BSc', 'MSc']);
    assert.equal(resolveClaimPath(data, ['missing']), undefined);
    assert.equal(resolveClaimPath(data, ['given_name', 'deeper']), undefined);
  });

  it('returns only the requested claims', () => {
    assert.deepEqual(selectClaims(data, [{ path: ['given_name'] }, { path: ['address', 'locality'] }, { path: ['degrees', null, 'name'] }, { path: ['missing'] }]), {
      given_name: 'Ada',
      address: { locality: 'London' },
      degrees: ['BSc', 'MSc'],
    });
  });

  it('returns everything but the registered claims when the query has no claims', () => {
    assert.deepEqual(selectClaims(credentialData({ _sd: ['digest'], address: { locality: 'London', _sd: ['x'] } }), undefined), {
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'ada@example.com',
      address: { locality: 'London' },
    });
  });
});

describe('holder subject', () => {
  it('uses the thumbprint URI of cnf.jwk or the DID behind cnf.kid', () => {
    assert.match(holderSubjectId({ jwk: HOLDER_JWK }) ?? '', /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]{43}$/);
    assert.equal(holderSubjectId({ kid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }), 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    assert.equal(holderSubjectId({ kid: 'https://issuer.example.com/keys/1' }), null);
    assert.equal(holderSubjectId({ jwk: { kty: 'EC' } }), null);
    assert.equal(holderSubjectId(undefined), null);
  });
});

describe('session evaluation', () => {
  it('treats anything but SUCCESSFUL and FAILED as undecided', () => {
    for (const status of ['UNUSED', 'ACTIVE', 'IN_USE', 'VALIDATING_RECEIVED_REQUEST', 'PROCESSING_FLOW', 'EXPIRED', 'UNKNOWN']) {
      assert.deepEqual(evaluateSession({ id: 'x', status }, query), { kind: 'undecided', status });
    }
    assert.deepEqual(evaluateSession({ id: 'x' }, query), { kind: 'undecided', status: 'UNKNOWN' });
  });

  it('reads a verified presentation', () => {
    const evaluation = evaluateSession(successfulSession('x'), query);
    assert.equal(evaluation.kind, 'verified');
    if (evaluation.kind !== 'verified') {
      return;
    }
    assert.match(evaluation.subjectId, /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:/);
    assert.equal(evaluation.issuer, 'did:web:issuer.example.com');
    assert.deepEqual(evaluation.claims, { given_name: 'Ada', email: 'ada@example.com', address: { locality: 'London' } });
    assert.equal(evaluation.presentationHash, presentationHash({ login: [SD_JWT_PRESENTATION] }));
  });

  it('reads a rejection, with the presentation hash when a presentation was received', () => {
    assert.deepEqual(evaluateSession(failedSession('x'), query), {
      kind: 'rejected',
      presentationHash: presentationHash({ login: [SD_JWT_PRESENTATION] }),
      failureType: 'presentation_validation',
    });
    assert.deepEqual(evaluateSession(failedSession('x', false), query), { kind: 'rejected', presentationHash: null, failureType: 'presentation_validation' });
    assert.deepEqual(evaluateSession({ status: 'FAILED', failure: { type: 'wallet_error_response', error: 'access_denied' } }, query), {
      kind: 'rejected',
      presentationHash: null,
      failureType: 'wallet_error_response',
    });
  });

  it('never turns an unusable successful session into a subject', () => {
    const inconsistent = (session: Record<string, unknown>, reason: RegExp) => {
      const evaluation = evaluateSession(session, query);
      assert.equal(evaluation.kind, 'inconsistent');
      assert.match((evaluation as { reason: string }).reason, reason);
    };
    const noRaw = successfulSession('x');
    delete noRaw['presented_raw_data'];
    inconsistent(noRaw, /presented_raw_data/);
    inconsistent(successfulSession('x', { credential: null }), /no presented credential/);
    inconsistent(successfulSession('x', { queryId: 'other' }), /no presented credential/);
    inconsistent(successfulSession('x', { credentialData: credentialData({ cnf: undefined }) }), /cnf/);
    inconsistent(successfulSession('x', { credentialData: credentialData({ cnf: { x5t: 'abc' } }) }), /cnf/);
    inconsistent(successfulSession('x', { credential: { type: 'vc-w3c', format: 'jwt_vc_json', credentialData: credentialData() } }), /not an SD-JWT VC/);
    inconsistent(successfulSession('x', { vpToken: { login: [1 as unknown as string] } }), /presented_raw_data/);
  });

  it('falls back to iss when the credential carries no issuer field', () => {
    const credential = { type: 'vc-sd_jwt', credentialData: credentialData({ iss: 'https://issuer.example.com' }) };
    const evaluation = evaluateSession(successfulSession('x', { credential }), query);
    assert.equal(evaluation.kind, 'verified');
    assert.equal((evaluation as { issuer: string | null }).issuer, 'https://issuer.example.com');
  });
});
