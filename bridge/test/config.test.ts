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
    assert.equal(config.firefly.registryApiName, undefined, 'no registry unless FIREFLY_REGISTRY_API is set');
    assert.deepEqual(Object.keys(config.queries), ['default', 'all']);
    assert.deepEqual(config.queries['default']?.dcql_query, QUERIES.default.dcql_query);
  });

  it('turns the on-chain issuer check on with FIREFLY_REGISTRY_API', () => {
    assert.equal(loadConfig(baseEnv({ FIREFLY_REGISTRY_API: ' trusted-issuer-registry ' })).firefly.registryApiName, 'trusted-issuer-registry');
    assert.equal(Object.hasOwn(loadConfig(baseEnv({ FIREFLY_REGISTRY_API: '' })).firefly, 'registryApiName'), false, 'empty is unset');
    assert.equal(Object.hasOwn(loadConfig(baseEnv({ FIREFLY_REGISTRY_API: '   ' })).firefly, 'registryApiName'), false, 'blank is unset');
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

  it('refuses to start with a query that could present several credentials', () => {
    const sdJwt = (id: string): Record<string, unknown> => ({ id, format: 'dc+sd-jwt', meta: { vct_values: [`https://issuer.example.com/credentials/${id}`] } });
    const withQuery = (dcql_query: Record<string, unknown>) => loadConfig(baseEnv({ BRIDGE_QUERIES: JSON.stringify({ default: { dcql_query } }) }));
    const refused = (dcql_query: Record<string, unknown>, message: RegExp) =>
      assert.throws(() => withQuery(dcql_query), (error: unknown) => error instanceof ConfigError && message.test(error.message), `expected ${message} for ${JSON.stringify(dcql_query)}`);

    // Without credential_sets every credential query is presented (OpenID4VP 1.0 §6.4).
    refused({ credentials: [sdJwt('a'), sdJwt('b')] }, /asks the wallet for 2 credentials \(a, b\); the bridge derives the subject from exactly one/);
    // A credential query may not return several credentials either.
    refused({ credentials: [{ ...sdJwt('a'), multiple: true }] }, /multiple cannot be true/);
    // credential_sets must pick exactly one credential.
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: {} }, /credential_sets must be an array of exactly one credential set/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [] }, /credential_sets must be an array of exactly one credential set/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [['a']] }, { options: [['b']] }] }, /exactly one credential set/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{}] }, /non-empty "options" array/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [] }] }, /non-empty "options" array/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [['a', 'b']] }] }, /every option must name exactly one credential query id \(one of a, b\)/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [['a'], ['c']] }] }, /every option must name exactly one credential query id/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [['a'], 'b'] }] }, /every option must name exactly one credential query id/);
    refused({ credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [['a'], ['b']], required: false }] }, /required cannot be false/);
    refused({ credentials: [sdJwt('a'), sdJwt('b'), sdJwt('c')], credential_sets: [{ options: [['a'], ['b']] }] }, /credential query c is not an option of credential_sets\[0\]/);

    // Accepted: one credential query, or one required set whose options each name one of them.
    assert.deepEqual(Object.keys(withQuery({ credentials: [sdJwt('a')] }).queries), ['default']);
    const oneOf = { credentials: [sdJwt('a'), sdJwt('b')], credential_sets: [{ options: [['a'], ['b']], required: true, purpose: 'either card' }] };
    assert.deepEqual(withQuery(oneOf).queries['default']?.dcql_query, oneOf, 'the query is passed to the verifier verbatim');
    assert.equal(withQuery({ credentials: [sdJwt('a')], credential_sets: [{ options: [['a']] }] }).queries['default']?.dcql_query.credentials.length, 1);
  });
});
