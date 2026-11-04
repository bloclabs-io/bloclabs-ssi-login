import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import { ZERO_HASH, presentationHash, sha256Hex, subjectCommitment } from '../src/crypto.js';
import { idempotencyKey } from '../src/firefly.js';
import {
  BLINDING_SECRET,
  credentialData,
  duplicateKey,
  failedSession,
  HOLDER_JWK,
  okOperation,
  QUERIES,
  requestBody,
  SD_JWT_PRESENTATION,
  SIGNING_KEY,
  sleep,
  startBridge,
  successfulSession,
  type TestBridge,
} from './helpers.js';

const EXPECTED_SUBJECT = /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]{43}$/;

describe('presentation requests', () => {
  let t: TestBridge;
  let counter = 0;
  const freshCorrelation = () => (counter++).toString(16).padStart(64, '0');

  before(async () => {
    t = await startBridge({ FIREFLY_AUTH_HEADER: 'Bearer firefly-proxy-token' });
  });
  after(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.firefly.invokes.length = 0;
    t.firefly.responses.length = 0;
  });

  async function open(overrides: Record<string, unknown> = {}): Promise<{ id: string; correlationId: string; walletUrl: string }> {
    const body = requestBody({ correlation_id: freshCorrelation(), ...overrides }, t.clock.now);
    const response = await t.call('POST', '/v1/presentation-requests', body);
    assert.equal(response.status, 201, JSON.stringify(response.body));
    const created = response.body as { id: string; wallet_url: string; dc_api: null };
    return { id: created.id, correlationId: body['correlation_id'] as string, walletUrl: created.wallet_url };
  }

  it('opens a verifier session for the attempt and returns the wallet URL', async () => {
    const expiresAt = new Date(t.clock.now + 180_000).toISOString();
    const body = requestBody({ correlation_id: freshCorrelation(), expires_at: expiresAt });
    const response = await t.call('POST', '/v1/presentation-requests', body);
    assert.equal(response.status, 201);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const created = response.body as { id: string; wallet_url: string; dc_api: null };
    assert.match(created.id, /^[0-9a-f-]{36}$/);
    assert.match(created.wallet_url, /^openid4vp:\/\/authorize\?client_id=/);
    assert.equal(created.dc_api, null);

    const setup = t.verifier.createCalls.at(-1)!;
    assert.equal(setup['flow_type'], 'cross_device');
    const core = setup['core_flow'] as Record<string, unknown>;
    assert.equal(core['sessionId'], created.id, 'the bridge chooses the session id so the callback URL can carry it');
    assert.deepEqual(core['dcql_query'], QUERIES.default.dcql_query);
    assert.deepEqual(core['policies'], QUERIES.default.policies);
    assert.equal(core['expiration_date'], expiresAt);
    assert.equal(core['retention_date'], new Date(t.clock.now + 240_000).toISOString());
    assert.equal(Object.hasOwn(core, 'reattemptable'), false, 'walt.id 1.2.0 rejects unknown keys');
    const webhook = (core['notifications'] as { webhook: { url: string; bearer_token: string } }).webhook;
    assert.equal(webhook.url, `${t.url}/v1/verifier-callbacks/${created.id}`);
    assert.ok(webhook.bearer_token.length >= 32);
    assert.equal(Object.hasOwn(setup, 'url_config'), false, 'the verifier keeps its configured public URLs');
  });

  it('validates the request body', async () => {
    const cases: Array<[Record<string, unknown> | string, number, string]> = [
      [requestBody({ correlation_id: 'abc' }), 400, 'invalid_request'],
      [requestBody({ correlation_id: undefined }), 400, 'invalid_request'],
      [requestBody({ correlation_id: freshCorrelation(), nonce: '' }), 400, 'invalid_request'],
      [requestBody({ correlation_id: freshCorrelation(), blinding_secret: undefined }), 400, 'invalid_request'],
      [requestBody({ correlation_id: freshCorrelation(), blinding_secret: 'tooshort' }), 400, 'invalid_request'],
      [requestBody({ correlation_id: freshCorrelation(), query: 'nope' }), 400, 'unknown_query'],
      [requestBody({ correlation_id: freshCorrelation(), query: '__proto__' }), 400, 'unknown_query'],
      [requestBody({ correlation_id: freshCorrelation(), expires_at: 'yesterday' }), 400, 'invalid_request'],
      [requestBody({ correlation_id: freshCorrelation(), expires_at: new Date(t.clock.now - 1000).toISOString() }), 400, 'invalid_request'],
      [requestBody({ correlation_id: freshCorrelation(), expires_at: new Date(t.clock.now + 2 * 86_400_000).toISOString() }), 400, 'invalid_request'],
      ['{"correlation_id": ', 400, 'invalid_json'],
      ['[]', 400, 'invalid_request'],
    ];
    for (const [body, status, code] of cases) {
      const response = await t.call('POST', '/v1/presentation-requests', body);
      assert.equal(response.status, status, JSON.stringify(body));
      assert.equal((response.body as { error: string }).error, code, JSON.stringify(body));
    }
    assert.equal(t.verifier.createCalls.length, 1, 'nothing reached the verifier');
  });

  it('never accepts the same correlation id twice', async () => {
    const correlationId = freshCorrelation();
    assert.equal((await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId }))).status, 201);
    const again = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId.toUpperCase() }));
    assert.equal(again.status, 409);
    assert.equal((again.body as { error: string }).error, 'duplicate_correlation_id');
  });

  it('answers 502 when the verifier cannot open a session, and releases the correlation id', async () => {
    const correlationId = freshCorrelation();
    t.verifier.failNextCreate = 400;
    const failed = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId }));
    assert.equal(failed.status, 502);
    assert.equal((failed.body as { error: string }).error, 'verifier_unavailable');
    const retried = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId }));
    assert.equal(retried.status, 201);
  });

  it('answers 409 until the wallet responded, and 404 for unknown requests', async () => {
    const { id } = await open();
    const pending = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(pending.status, 409);
    assert.deepEqual(pending.body, { error: 'pending' });
    const unknown = await t.call('GET', '/v1/presentation-requests/no-such-request/result');
    assert.equal(unknown.status, 404);
    assert.deepEqual(unknown.body, { error: 'not_found' });
  });

  it('attests a verified presentation and only then serves the result', async () => {
    const { id, correlationId } = await open();
    const vpToken = { login: [SD_JWT_PRESENTATION] };
    t.verifier.setSession(id, successfulSession(id, { vpToken }));

    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    t.firefly.responses.push(async () => {
      await held;
      return okOperation();
    });

    assert.equal(await t.verifier.fireCallback(id), 202);
    await sleep(50);
    assert.equal(t.firefly.invokes.length, 1, 'the attest call is in flight');
    const early = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(early.status, 409, 'no result before FireFly accepted the attestation');

    release();
    await t.bridge.idle();

    const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(result.status, 200);
    const body = result.body as { subject_id: string; issuer: string; presentation_hash: string; claims: Record<string, unknown> };
    assert.match(body.subject_id, EXPECTED_SUBJECT);
    assert.equal(body.issuer, 'did:web:issuer.example.com');
    assert.equal(body.presentation_hash, presentationHash(vpToken));
    assert.equal(body.presentation_hash, sha256Hex(`{"login":[${JSON.stringify(SD_JWT_PRESENTATION)}]}`));
    assert.deepEqual(body.claims, { given_name: 'Ada', email: 'ada@example.com', address: { locality: 'London' } }, 'only what the query asked for');

    const invoke = t.firefly.invokes[0]!;
    assert.equal(invoke.path, '/api/v1/namespaces/default/apis/ssi-login-attestor/invoke/attest?confirm=true');
    assert.equal(invoke.headers['authorization'], 'Bearer firefly-proxy-token');
    assert.deepEqual(invoke.body, {
      key: SIGNING_KEY,
      input: {
        correlationId: '0x' + correlationId,
        result: 1,
        subjectCommitment: '0x' + subjectCommitment(correlationId, BLINDING_SECRET, body.subject_id),
        presentationHash: '0x' + body.presentation_hash,
      },
      idempotencyKey: idempotencyKey(correlationId),
    });
  });

  it('attests once however many callbacks the verifier sends', async () => {
    const { id } = await open();
    for (const event of ['authorization_request_requested', 'attempted_presentation']) {
      t.verifier.setSession(id, { ...successfulSession(id), status: event === 'attempted_presentation' ? 'PROCESSING_FLOW' : 'IN_USE' });
      assert.equal(await t.verifier.fireCallback(id, event), 202);
    }
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 0, 'nothing to attest while the session is in flight');

    t.verifier.setSession(id, successfulSession(id));
    await Promise.all([
      t.verifier.fireCallback(id, 'presentation_fulfils_dcql_query'),
      t.verifier.fireCallback(id, 'credential_policy_results_available'),
      t.verifier.fireCallback(id, 'credential_policy_results_available'),
    ]);
    await t.bridge.idle();
    assert.equal(await t.verifier.fireCallback(id), 202, 'late duplicates are still acknowledged');
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 1);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200);
  });

  it('retries a failed attest call with the same idempotency key and trusts the earlier transaction', async () => {
    const { id, correlationId } = await open();
    t.verifier.setSession(id, successfulSession(id));
    const transactionId = '7b1d2c1e-1111-4222-8333-444444444444';
    t.firefly.responses.push(
      () => ({ status: 500, body: { error: 'FF10111: simulated outage' } }),
      () => duplicateKey(transactionId),
    );
    await t.verifier.fireCallback(id);
    await t.bridge.idle();

    assert.equal(t.firefly.invokes.length, 2);
    assert.equal(t.firefly.invokes[0]!.body['idempotencyKey'], idempotencyKey(correlationId));
    assert.equal(t.firefly.invokes[1]!.body['idempotencyKey'], idempotencyKey(correlationId));
    assert.deepEqual(t.firefly.statusCalls.filter((call) => call === transactionId), [transactionId]);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200);
  });

  it('retries when the connection drops while FireFly is answering', async () => {
    const { id, correlationId } = await open();
    t.verifier.setSession(id, successfulSession(id));
    const transactionId = '1d7b0000-3333-4444-8555-666666666666';
    t.firefly.responses.push(() => ({ ...okOperation(), truncate: true }), () => duplicateKey(transactionId));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();

    assert.equal(t.firefly.invokes.length, 2, 'the cut-off answer is retried with the same key');
    assert.equal(t.firefly.invokes[1]!.body['idempotencyKey'], idempotencyKey(correlationId));
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200);
  });

  it('treats a duplicate key whose earlier transaction failed as a failed attestation', async () => {
    const { id } = await open();
    t.verifier.setSession(id, successfulSession(id));
    const transactionId = '9c2b0000-2222-4333-8444-555555555555';
    t.firefly.transactionStatus.set(transactionId, 'Failed');
    t.firefly.responses.push(() => ({ status: 503, body: { error: 'FF10284: timeout' } }), () => duplicateKey(transactionId));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();

    assert.equal(t.firefly.invokes.length, 2);
    const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(result.status, 404);
    assert.deepEqual(result.body, { error: 'failed' });
  });

  it('does not retry when FireFly refuses the call outright', async () => {
    const { id } = await open();
    t.verifier.setSession(id, successfulSession(id));
    t.firefly.responses.push(() => ({ status: 400, body: { error: 'FF10111: bad key' } }));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 1);
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'failed' });
  });

  it('gives up after the retries are used up, and never serves a result', async () => {
    const { id } = await open();
    t.verifier.setSession(id, successfulSession(id));
    t.firefly.responses.push(
      () => ({ status: 502, body: { error: 'FF10284: down' } }),
      () => ({ status: 502, body: { error: 'FF10284: down' } }),
      () => ({ status: 502, body: { error: 'FF10284: down' } }),
    );
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 3);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 404);
  });

  it('attests a rejection with result 2 and serves no result', async () => {
    const { id, correlationId } = await open();
    t.verifier.setSession(id, failedSession(id));
    await t.verifier.fireCallback(id, 'presentation_validation_failed');
    await t.bridge.idle();

    assert.equal(t.firefly.invokes.length, 1);
    assert.deepEqual(t.firefly.invokes[0]!.body['input'], {
      correlationId: '0x' + correlationId,
      result: 2,
      subjectCommitment: '0x' + ZERO_HASH,
      presentationHash: '0x' + presentationHash({ login: [SD_JWT_PRESENTATION] }),
    });
    const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(result.status, 404);
    assert.deepEqual(result.body, { error: 'rejected' });

    // A declined request (OpenID4VP error response) has no presentation to hash.
    const declined = await open();
    t.verifier.setSession(declined.id, failedSession(declined.id, false));
    await t.verifier.fireCallback(declined.id, 'wallet_error_response_received');
    await t.bridge.idle();
    assert.equal((t.firefly.invokes[1]!.body['input'] as Record<string, unknown>)['presentationHash'], '0x' + ZERO_HASH);
    assert.equal((t.firefly.invokes[1]!.body['input'] as Record<string, unknown>)['result'], 2);
  });

  it('never attests a successful session it cannot turn into a subject', async () => {
    const { id } = await open();
    t.verifier.setSession(id, successfulSession(id, { credentialData: credentialData({ cnf: undefined }) }));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 0);
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'failed' });
  });

  it('uses the DID behind cnf.kid as the subject', async () => {
    const { id, correlationId } = await open();
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    t.verifier.setSession(id, successfulSession(id, { credentialData: credentialData({ cnf: { kid: `${did}#${did.slice(8)}` } }) }));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal((result.body as { subject_id: string }).subject_id, did);
    assert.equal((t.firefly.invokes[0]!.body['input'] as Record<string, string>)['subjectCommitment'], '0x' + subjectCommitment(correlationId, BLINDING_SECRET, did));
  });

  it('returns every disclosed claim but the registered ones for a query without claims', async () => {
    const { id } = await open({ query: 'all' });
    t.verifier.setSession(id, successfulSession(id, { queryId: 'any' }));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(result.status, 200);
    assert.deepEqual((result.body as { claims: unknown }).claims, {
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'ada@example.com',
      address: { locality: 'London', street_address: '12 St James Square' },
    });
    assert.match((result.body as { subject_id: string }).subject_id, EXPECTED_SUBJECT);
    assert.ok(HOLDER_JWK.x, 'fixture key present');
  });

  it('fails a request whose session the verifier no longer has', async () => {
    const { id } = await open();
    const stored = t.verifier.sessions.get(id)!;
    t.verifier.sessions.delete(id);
    const response = await fetch(`${t.url}/v1/verifier-callbacks/${id}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${((stored.setup['core_flow'] as Record<string, unknown>)['notifications'] as { webhook: { bearer_token: string } }).webhook.bearer_token}` },
    });
    assert.equal(response.status, 202);
    await response.text();
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 0);
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'failed' });
  });

  it('retries a transient session read before giving up on the callback', async () => {
    const { id } = await open();
    t.verifier.setSession(id, successfulSession(id));
    t.verifier.failNextInfo = 2;
    const reads = t.verifier.infoCalls.length;
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal(t.verifier.infoCalls.length - reads, 3, 'two failures, then the read that settles it');
    assert.equal(t.firefly.invokes.length, 1);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200);
  });

  it('rechecks on the next sweep when the verifier stayed unreachable', async () => {
    const { id } = await open();
    t.verifier.setSession(id, successfulSession(id));
    t.verifier.failNextInfo = 10;
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 0);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 409, 'still pending');

    t.verifier.failNextInfo = 0;
    t.bridge.sweep();
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 1, 'the sweep retried the callback');
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200);
    t.bridge.sweep();
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 1, 'a settled request is not rechecked');
  });
});

describe('expiry', () => {
  let t: TestBridge;
  before(async () => {
    t = await startBridge();
  });
  after(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.firefly.invokes.length = 0;
  });

  it('deletes a result after the attempt lifetime plus a minute', async () => {
    const start = t.clock.now;
    const opened = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: 'e'.repeat(64) }, start));
    const id = (opened.body as { id: string }).id;
    t.verifier.setSession(id, successfulSession(id));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200);

    t.clock.now = start + 180_000 + 59_000;
    assert.equal(t.bridge.sweep(), 0);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 200, 'still readable a minute after expiry');

    t.clock.now = start + 180_000 + 60_000;
    assert.equal(t.bridge.sweep(), 1);
    assert.equal((await t.call('GET', `/v1/presentation-requests/${id}/result`)).status, 404, 'gone after the grace period');
    t.clock.now = start;
  });

  it('does not attest a wallet response that arrives after the attempt expired', async () => {
    const start = t.clock.now;
    const opened = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: 'f'.repeat(64) }, start));
    const id = (opened.body as { id: string }).id;
    t.clock.now = start + 180_000;
    t.verifier.setSession(id, successfulSession(id));
    await t.verifier.fireCallback(id);
    await t.bridge.idle();
    assert.equal(t.firefly.invokes.length, 0);
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'failed' });
    t.clock.now = start;
  });

  it('remembers a correlation id for a day, then forgets it', async () => {
    const start = t.clock.now;
    const correlationId = 'd'.repeat(64);
    assert.equal((await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId }, start))).status, 201);
    t.clock.now = start + 3_600_000;
    t.bridge.sweep();
    assert.equal((await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId }, t.clock.now))).status, 409);
    t.clock.now = start + 24 * 3_600_000;
    t.bridge.sweep();
    assert.equal((await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId }, t.clock.now))).status, 201);
    t.clock.now = start;
  });
});
