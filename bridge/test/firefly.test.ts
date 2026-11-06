import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { FireFlyConfig } from '../src/config.js';
import { FireFlyClient, FireFlyError } from '../src/firefly.js';

interface Recorded {
  url: string;
  method: string | undefined;
  headers: Record<string, string>;
  body: unknown;
}

/** A FireFlyClient over a fake fetch that answers every call with `answer`. */
/** `registryApiName` null leaves FIREFLY_REGISTRY_API unset. */
function client(answer: (call: Recorded) => Response, registryApiName: string | null = 'trusted-issuer-registry'): { firefly: FireFlyClient; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const config: FireFlyConfig = {
    url: 'http://firefly.test:5000',
    namespace: 'login',
    apiName: 'ssi-login-attestor',
    signingKey: '0x1111111111111111111111111111111111111111',
    authHeader: 'Bearer proxy',
  };
  if (registryApiName !== null) {
    config.registryApiName = registryApiName;
  }
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const call: Recorded = {
      url: String(input),
      method: init?.method,
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : init?.body,
    };
    calls.push(call);
    return answer(call);
  }) as typeof fetch;
  return { firefly: new FireFlyClient(config, fetchImpl, 1_000, 1_000), calls };
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

async function rejectsWith(promise: Promise<unknown>, retryable: boolean, status: number | null, message: RegExp): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof FireFlyError, `expected a FireFlyError, got ${String(error)}`);
    assert.equal(error.retryable, retryable, `retryable: ${error.message}`);
    assert.equal(error.status, status, `status: ${error.message}`);
    assert.match(error.message, message);
    return true;
  });
}

describe('FireFlyClient.isTrusted', () => {
  it('queries isTrusted on the registry API with the issuer and the vct, and returns the contract\'s answer', async () => {
    const { firefly, calls } = client(() => json(200, { output: true }));
    assert.equal(await firefly.isTrusted('did:web:issuer.example.com', 'https://issuer.example.com/credentials/login'), true);
    assert.equal(calls.length, 1);
    const call = calls[0]!;
    assert.equal(call.url, 'http://firefly.test:5000/api/v1/namespaces/login/apis/trusted-issuer-registry/query/isTrusted');
    assert.equal(call.method, 'POST');
    assert.equal(call.headers['Authorization'], 'Bearer proxy');
    assert.equal(call.headers['Content-Type'], 'application/json');
    assert.deepEqual(call.body, { input: { issuer: 'did:web:issuer.example.com', vct: 'https://issuer.example.com/credentials/login' } });

    assert.equal(await client(() => json(200, { output: false })).firefly.isTrusted('did:web:x', 'vct'), false);
  });

  it('encodes the API name into the path', async () => {
    const { firefly, calls } = client(() => json(200, { output: false }), 'registry/with space');
    await firefly.isTrusted('a', 'b');
    assert.equal(calls[0]!.url, 'http://firefly.test:5000/api/v1/namespaces/login/apis/registry%2Fwith%20space/query/isTrusted');
  });

  it('treats anything but a boolean output as no decision, not to be retried', async () => {
    for (const body of [{ output: 'true' }, { output: 'false' }, { output: 1 }, { output: null }, {}, [true], 'true']) {
      await rejectsWith(client(() => json(200, body)).firefly.isTrusted('a', 'b'), false, 200, /without a boolean output/);
    }
    await rejectsWith(client(() => new Response('<html>', { status: 200 })).firefly.isTrusted('a', 'b'), false, 200, /without a boolean output/);
  });

  it('reports a refused query as final and a FireFly failure as retryable', async () => {
    await rejectsWith(client(() => json(404, { error: 'FF10109: Not found' })).firefly.isTrusted('a', 'b'), false, 404, /could not be queried: FF10109/);
    await rejectsWith(client(() => json(400, { error: 'FF10111: Error from blockchain: execution reverted' })).firefly.isTrusted('a', 'b'), false, 400, /FF10111/);
    await rejectsWith(client(() => json(503, { error: 'FF10284: timeout' })).firefly.isTrusted('a', 'b'), true, 503, /FF10284/);
    await rejectsWith(client(() => new Response('bad gateway', { status: 502 })).firefly.isTrusted('a', 'b'), true, 502, /HTTP 502 bad gateway/);
  });

  it('reports an unreachable FireFly as retryable', async () => {
    const { firefly } = client(() => {
      throw new TypeError('fetch failed');
    });
    await rejectsWith(firefly.isTrusted('a', 'b'), true, null, /unreachable: fetch failed/);
  });

  it('refuses to query without a configured registry', async () => {
    const { firefly, calls } = client(() => json(200, { output: true }), null);
    await rejectsWith(firefly.isTrusted('a', 'b'), false, null, /No trusted-issuer registry is configured/);
    assert.equal(calls.length, 0);
  });
});
