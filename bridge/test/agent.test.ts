/**
 * The agent credential query (ADR 0007): the profile WordPress asks for by name,
 * the credential's expiry on the result, and the registry pair (issuer, vct).
 */

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';

import { presentationHash } from '../src/crypto.js';
import {
  credentialData,
  ISSUER,
  QUERIES,
  registryKey,
  requestBody,
  SD_JWT_PRESENTATION,
  startBridge,
  successfulSession,
  VCT,
  type TestBridge,
} from './helpers.js';

const AGENT_VCT = 'https://issuer.example.com/credentials/agent';
const ACTS_FOR = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:principal';
const AGENT_NAME = 'Nightly backup';
const AGENT_OPERATOR = 'Ada Lovelace';

const AGENT_QUERY = {
  dcql_query: {
    credentials: [{
      id: 'agent',
      format: 'dc+sd-jwt',
      meta: { vct_values: [AGENT_VCT] },
      claims: [
        { path: ['acts_for'] },
        { path: ['scope'] },
        { path: ['agent', 'name'] },
        { path: ['agent', 'operator'] },
      ],
    }],
  },
  policies: { vc_policies: ['signature', 'expiration', 'not-before'] },
};

function agentCredential(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return credentialData({
    vct: AGENT_VCT,
    acts_for: ACTS_FOR,
    scope: ['read', 'content'],
    agent: { name: AGENT_NAME, operator: AGENT_OPERATOR },
    ...overrides,
  });
}

describe('agent presentation requests', () => {
  let t: TestBridge;
  let counter = 0x20000;
  const freshCorrelation = () => (counter++).toString(16).padStart(64, '0');

  before(async () => {
    t = await startBridge({
      FIREFLY_REGISTRY_API: 'trusted-issuer-registry',
      BRIDGE_QUERIES: JSON.stringify({ ...QUERIES, agent: AGENT_QUERY }),
    });
  });
  after(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.logs.length = 0;
    t.firefly.invokes.length = 0;
    t.firefly.responses.length = 0;
    t.firefly.queries.length = 0;
    t.firefly.queryResponses.length = 0;
    t.firefly.trusted.clear();
    t.verifier.createCalls.length = 0;
  });

  async function present(credential: Record<string, unknown>, query = 'agent'): Promise<{ id: string }> {
    const body = requestBody({ correlation_id: freshCorrelation(), query }, t.clock.now);
    const response = await t.call('POST', '/v1/presentation-requests', body);
    assert.equal(response.status, 201, JSON.stringify(response.body));
    const id = (response.body as { id: string }).id;
    t.verifier.setSession(id, successfulSession(id, { queryId: 'agent', credentialData: credential }));
    assert.equal(await t.verifier.fireCallback(id), 202);
    await t.bridge.idle();
    return { id };
  }

  it('asks walt.id for the agent query, and not for the profile flag', async () => {
    const body = requestBody({ correlation_id: freshCorrelation(), query: 'agent' }, t.clock.now);
    const response = await t.call('POST', '/v1/presentation-requests', body);
    assert.equal(response.status, 201, JSON.stringify(response.body));
    const setup = t.verifier.createCalls[0]!['core_flow'] as Record<string, unknown>;
    assert.deepEqual(setup['dcql_query'], AGENT_QUERY.dcql_query);
    assert.equal(JSON.stringify(setup).includes('profile'), false);
  });

  it('checks the presented issuer and agent vct on chain, and returns the claims and the expiry', async () => {
    t.firefly.trusted.add(registryKey(ISSUER, AGENT_VCT));
    // A login type the same issuer may issue must not satisfy the agent query.
    t.firefly.trusted.add(registryKey(ISSUER, VCT));
    const { id } = await present(agentCredential());

    assert.equal(t.firefly.queries.length, 1);
    assert.deepEqual(t.firefly.queries[0]!.body, { input: { issuer: ISSUER, vct: AGENT_VCT } });
    assert.equal((t.firefly.invokes[0]!.body['input'] as Record<string, unknown>)['result'], 1);

    const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
    assert.equal(result.status, 200);
    const body = result.body as { expires_at?: string; claims: Record<string, unknown>; presentation_hash: string };
    assert.equal(body.expires_at, new Date(1_793_536_000 * 1000).toISOString());
    assert.deepEqual(body.claims, {
      acts_for: ACTS_FOR,
      scope: ['read', 'content'],
      agent: { name: AGENT_NAME, operator: AGENT_OPERATOR },
    });
    assert.equal(body.presentation_hash, presentationHash({ agent: [SD_JWT_PRESENTATION] }));

    const output = t.logs.join('\n');
    assert.equal(output.includes(ACTS_FOR), false, 'the principal is not logged');
    assert.equal(output.includes(AGENT_NAME), false, 'the agent label is not logged');
    assert.equal(output.includes(AGENT_OPERATOR), false, 'the operator is not logged');
    assert.equal(output.includes(AGENT_VCT), false, 'the credential type is not logged');
    assert.equal(output.includes(ISSUER), false, 'the issuer is not logged');
  });

  it('rejects an agent type the registry does not trust, even when the issuer is trusted for another type', async () => {
    t.firefly.trusted.add(registryKey(ISSUER, VCT));
    const { id } = await present(agentCredential());

    assert.deepEqual(t.firefly.queries[0]!.body, { input: { issuer: ISSUER, vct: AGENT_VCT } });
    assert.equal((t.firefly.invokes[0]!.body['input'] as Record<string, unknown>)['result'], 2);
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'rejected' });
  });

  it('does not attest, or ask the registry, when the presented type is not the one the query pins', async () => {
    t.firefly.trusted.add(registryKey(ISSUER, VCT));
    t.firefly.trusted.add(registryKey(ISSUER, AGENT_VCT));
    const { id } = await present(agentCredential({ vct: VCT }));

    assert.equal(t.firefly.queries.length, 0, 'a login credential is not an agent credential');
    assert.equal(t.firefly.invokes.length, 0, 'nothing is attested');
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'failed' });
    assert.ok(t.logs.some((line) => line.includes('presented vct is not one the agent query pins')));
    assert.equal(t.logs.join('\n').includes(VCT), false);
  });

  it('does not attest an agent credential that has no NumericDate exp', async () => {
    t.firefly.trusted.add(registryKey(ISSUER, AGENT_VCT));
    const { id } = await present(agentCredential({ exp: undefined }));

    assert.equal(t.firefly.queries.length, 0);
    assert.equal(t.firefly.invokes.length, 0);
    assert.deepEqual((await t.call('GET', `/v1/presentation-requests/${id}/result`)).body, { error: 'failed' });
    assert.ok(t.logs.some((line) => line.includes('agent credential has no NumericDate exp')));
  });
});
