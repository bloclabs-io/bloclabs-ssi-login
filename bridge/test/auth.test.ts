import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { requestBody, startBridge, type TestBridge } from './helpers.js';

describe('authentication', () => {
  let t: TestBridge;
  before(async () => {
    t = await startBridge();
  });
  after(async () => {
    await t.close();
  });

  it('refuses to open a request without the Authorization header', async () => {
    const response = await fetch(`${t.url}/v1/presentation-requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody()),
    });
    assert.equal(response.status, 401);
    assert.equal(response.headers.get('www-authenticate'), 'Bearer realm="bloclabs-ssi-bridge"');
    assert.deepEqual(await response.json(), { error: 'unauthorized' });
    assert.equal(t.verifier.createCalls.length, 0, 'no verifier session was opened');
  });

  it('refuses a wrong token, and the token in another scheme', async () => {
    for (const authorization of ['Bearer wrong', `Basic ${Buffer.from('x:y').toString('base64')}`, 'test-bridge-token-0123456789abcdef0123456789abcdef', '']) {
      const response = await fetch(`${t.url}/v1/presentation-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: authorization },
        body: JSON.stringify(requestBody()),
      });
      assert.equal(response.status, 401, `authorization "${authorization}"`);
      await response.text();
    }
    assert.equal(t.verifier.createCalls.length, 0);
  });

  it('refuses to serve a result without the header', async () => {
    const response = await fetch(`${t.url}/v1/presentation-requests/some-id/result`);
    assert.equal(response.status, 401);
    await response.text();
  });

  it('does not accept the WordPress token on the verifier callback route', async () => {
    const opened = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: 'a'.repeat(64) }));
    assert.equal(opened.status, 201);
    const id = (opened.body as { id: string }).id;
    const response = await t.call('POST', `/v1/verifier-callbacks/${id}`, { target: id, event: 'x', session: {} });
    assert.equal(response.status, 401);
    const unknown = await fetch(`${t.url}/v1/verifier-callbacks/no-such-id`, { method: 'POST', headers: { Authorization: 'Bearer x' } });
    assert.equal(unknown.status, 404);
    await unknown.text();
  });

  it('answers the health check without authentication and nothing else', async () => {
    const health = await fetch(`${t.url}/healthz`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'ok' });
    const missing = await fetch(`${t.url}/v1/other`);
    assert.equal(missing.status, 404);
    await missing.text();
    const wrongMethod = await t.call('DELETE', '/v1/presentation-requests');
    assert.equal(wrongMethod.status, 405);
  });
});
