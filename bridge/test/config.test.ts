import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ConfigError, loadConfig } from '../src/config.js';
import { baseEnv, QUERIES } from './helpers.js';

describe('configuration', () => {
  it('loads a complete environment', () => {
    const config = loadConfig(baseEnv({ FIREFLY_AUTH_HEADER: 'Bearer proxy', BRIDGE_PORT: '9000' }));
    assert.equal(config.listenPort, 9000);
    assert.equal(config.firefly.namespace, 'default');
    assert.equal(config.firefly.apiName, 'ssi-login-attestor');
    assert.equal(config.firefly.authHeader, 'Bearer proxy');
    assert.deepEqual(Object.keys(config.queries), ['default', 'all']);
    assert.deepEqual(config.queries['default']?.dcql_query, QUERIES.default.dcql_query);
  });

  it('refuses to start without the WordPress auth token', () => {
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_AUTH_TOKEN: undefined })), (error: unknown) =>
      error instanceof ConfigError && /BRIDGE_AUTH_TOKEN is required/.test(error.message));
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_AUTH_TOKEN: 'short' })), /at least 32 characters/);
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_AUTH_TOKEN: '   ' })), /BRIDGE_AUTH_TOKEN is required/);
  });

  it('requires the verifier, FireFly and callback settings', () => {
    assert.throws(() => loadConfig(baseEnv({ VERIFIER_URL: undefined })), /VERIFIER_URL is required/);
    assert.throws(() => loadConfig(baseEnv({ VERIFIER_URL: 'verifier:7004' })), /VERIFIER_URL must be an absolute http\(s\) URL/);
    assert.throws(() => loadConfig(baseEnv({ FIREFLY_URL: undefined })), /FIREFLY_URL is required/);
    assert.throws(() => loadConfig(baseEnv({ FIREFLY_SIGNING_KEY: undefined })), /FIREFLY_SIGNING_KEY is required/);
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_CALLBACK_URL: 'ftp://bridge/x' })), /BRIDGE_CALLBACK_URL must be an absolute http\(s\) URL/);
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_PORT: '70000' })), /BRIDGE_PORT/);
  });

  it('validates the query definitions', () => {
    const withQueries = (queries: unknown) => loadConfig(baseEnv({ BRIDGE_QUERIES: JSON.stringify(queries) }));
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_QUERIES: undefined })), /BRIDGE_QUERIES is required/);
    assert.throws(() => loadConfig(baseEnv({ BRIDGE_QUERIES: '{not json' })), /not valid JSON/);
    assert.throws(() => withQueries({ other: QUERIES.default }), /must define a query named "default"/);
    assert.throws(() => withQueries({ default: { policies: {} } }), /must be an object with a "dcql_query"/);
    assert.throws(() => withQueries({ default: { dcql_query: { credentials: [] } } }), /credentials must be a non-empty array/);
    assert.throws(() => withQueries({ default: { dcql_query: { credentials: [{ id: 'a', format: 'mso_mdoc', meta: {} }] } } }), /format must be one of dc\+sd-jwt/);
    assert.throws(
      () => withQueries({ default: { dcql_query: { credentials: [{ id: 'a', format: 'dc+sd-jwt', meta: {}, require_cryptographic_holder_binding: false }] } } }),
      /require_cryptographic_holder_binding cannot be false/,
    );
    assert.throws(() => withQueries({ default: { dcql_query: { credentials: [{ id: 'a', format: 'dc+sd-jwt', meta: {}, claims: [] }] } } }), /claims must be a non-empty array/);
    assert.throws(() => withQueries({ default: { dcql_query: { credentials: [{ id: 'a', format: 'dc+sd-jwt', meta: {}, claims: [{ path: [] }] }] } } }), /non-empty "path"/);
    assert.throws(() => withQueries({ 'bad name': QUERIES.default }), /query name "bad name"/);
    assert.throws(() => withQueries({ default: { ...QUERIES.default, policies: 'signature' } }), /policies must be an object/);
  });
});
