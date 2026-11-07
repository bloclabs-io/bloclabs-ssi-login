import test from 'node:test';
import assert from 'node:assert/strict';

import { offerRequest } from './agent-offer.mjs';

test('the agent offer uses the agent profile and carries no acts_for unless asked', () => {
	assert.deepEqual(offerRequest(''), { profileId: 'agent', authMethod: 'PRE_AUTHORIZED', expiresInSeconds: 3600 });
	assert.deepEqual(offerRequest(undefined).runtimeOverrides, undefined);
});

test('a delegated offer names the principal by subject id, and nothing else passes', () => {
	const did = 'did:jwk:eyJrdHkiOiJFQyJ9';
	assert.deepEqual(offerRequest(` ${did}\r\n`).runtimeOverrides, { credentialData: { acts_for: did } });
	assert.equal(offerRequest('urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs').runtimeOverrides.credentialData.acts_for.startsWith('urn:'), true);
	assert.throws(() => offerRequest('ada@example.com'), /ACTS_FOR must be a DID/);
	assert.throws(() => offerRequest('did:jwk:x"y'), /ACTS_FOR must be a DID/);
});
