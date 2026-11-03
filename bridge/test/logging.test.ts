import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { AUTH_TOKEN, BLINDING_SECRET, requestBody, SD_JWT_PRESENTATION, startBridge, successfulSession } from './helpers.js';

describe('logging', () => {
  it('logs a whole login without claims, subjects, presentations, nonces or tokens', async () => {
    const t = await startBridge();
    try {
      const correlationId = 'c0ffee'.repeat(10) + 'c0ff';
      const nonce = 'wp-nonce-SECRET-q2F8kZ0';
      const opened = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: correlationId, nonce }, t.clock.now));
      const id = (opened.body as { id: string }).id;
      const callbackToken = (((t.verifier.createCalls[0]!['core_flow'] as Record<string, unknown>)['notifications']) as { webhook: { bearer_token: string } }).webhook.bearer_token;

      t.verifier.setSession(id, successfulSession(id));
      await t.verifier.fireCallback(id, 'attempted_presentation');
      await t.verifier.fireCallback(id);
      await t.bridge.idle();
      const result = await t.call('GET', `/v1/presentation-requests/${id}/result`);
      assert.equal(result.status, 200);
      const subject = (result.body as { subject_id: string }).subject_id;

      // A rejected one too: failure reasons from the verifier may quote values.
      const rejected = await t.call('POST', '/v1/presentation-requests', requestBody({ correlation_id: 'd'.repeat(64) }, t.clock.now));
      const rejectedId = (rejected.body as { id: string }).id;
      t.verifier.setSession(rejectedId, { id: rejectedId, status: 'FAILED', failure: { type: 'presentation_validation', reason: `Expected verifier-nonce, got ${nonce}` } });
      await t.verifier.fireCallback(rejectedId);
      await t.bridge.idle();

      const output = t.logs.join('\n');
      assert.ok(output.includes(id), 'request ids are logged');
      assert.ok(output.includes('decision attested'), 'decisions are logged');
      for (const secret of ['Ada', 'Lovelace', 'ada@example.com', 'London', subject, SD_JWT_PRESENTATION, 'verifier-nonce', nonce, BLINDING_SECRET, AUTH_TOKEN, callbackToken, correlationId, 'did:web:issuer.example.com']) {
        assert.equal(output.includes(secret), false, `logs must not contain ${secret.slice(0, 12)}…`);
      }
    } finally {
      await t.close();
    }
  });
});
