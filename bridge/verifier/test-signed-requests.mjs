/** Live smoke test: npm run build && node verifier/test-signed-requests.mjs (Docker + OpenSSL). */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID, verify, X509Certificate } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { buildSessionSetup, VerifierClient } from '../dist/src/verifier.js';

// Honor Docker's default host/context, including Docker Desktop and DOCKER_HOST.
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8' }).trim();
const dir = mkdtempSync(join(tmpdir(), 'bridge-live-signing-'));
const key = join(dir, 'key.pem');
const cert = join(dir, 'cert.pem');
try {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=verifier.example.com',
    '-addext', 'subjectAltName=DNS:verifier.example.com'], { stdio: 'ignore' });
  const leaf = new X509Certificate(readFileSync(cert));
  for (const mode of ['unsigned', 'x509_san_dns', 'x509_hash']) {
    const configDir = join(dir, mode);
    cpSync(resolve('verifier'), configDir, { recursive: true, filter: (path) => !path.includes('/private') });
    const configPath = join(configDir, 'verifier-service.conf');
    if (mode === 'unsigned') {
      writeFileSync(configPath, JSON.stringify({ urlPrefix: 'https://verifier.example.com/verification-session', urlHost: 'openid4vp://authorize' }));
    } else {
      rmSync(configPath);
      execFileSync(process.execPath, ['verifier/configure-signing.mjs', '--key', key, '--cert', cert,
        '--url', 'https://verifier.example.com', '--mode', mode, '--output', configPath]);
    }
    const container = docker('run', '-d', '--rm', '-p', '127.0.0.1::7004',
      '-v', `${configDir}:/waltid-verifier-api2/config:ro`, 'waltid/verifier-api2:1.2.0');
    try {
      const port = docker('port', container, '7004/tcp').split(':').at(-1);
      const base = `http://127.0.0.1:${port}`;
      let ready = false;
      for (let i = 0; i < 90; i++) {
        try { await fetch(base, { signal: AbortSignal.timeout(1000) }); ready = true; break; } catch { await setTimeout(1000); }
      }
      assert.ok(ready, 'verifier did not start');
      const id = randomUUID();
      const query = { dcql_query: { credentials: [{ id: 'login', format: 'dc+sd-jwt', meta: { vct_values: ['https://issuer.example.com/login'] } }] } };
      const setup = buildSessionSetup({ id, query, signedRequest: mode !== 'unsigned',
        expiresAt: new Date(Date.now() + 180000), retainUntil: new Date(Date.now() + 240000),
        webhookUrl: 'http://localhost:1/callback', webhookToken: 'test-only' });
      const created = await new VerifierClient(base).createSession(setup);
      const bootstrap = new URL(created.walletUrl);
      const requestUri = new URL(bootstrap.searchParams.get('request_uri'));
      assert.equal(requestUri.origin, 'https://verifier.example.com');
      const response = await fetch(base + requestUri.pathname, { signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200);
      const raw = await response.text();
      const expectedDcql = { credentials: [{ ...query.dcql_query.credentials[0], multiple: false,
        require_cryptographic_holder_binding: true, meta: { ...query.dcql_query.credentials[0].meta, format: 'dc+sd-jwt' } }] };
      if (mode === 'unsigned') {
        const request = JSON.parse(raw);
        assert.match(request.client_id, /^redirect_uri:/);
        assert.deepEqual(request.dcql_query, expectedDcql);
      } else {
        assert.match(response.headers.get('content-type'), /application\/oauth-authz-req\+jwt/);
        const parts = raw.split('.');
        assert.equal(parts.length, 3);
        const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
        const request = JSON.parse(Buffer.from(parts[1], 'base64url'));
        assert.equal(header.alg, 'ES256');
        assert.equal(header.typ, 'oauth-authz-req+jwt');
        assert.deepEqual(header.x5c, [leaf.raw.toString('base64')]);
        assert.ok(verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`),
          { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url')));
        assert.equal(request.client_id, mode + ':' + (mode === 'x509_san_dns' ? 'verifier.example.com'
          : createHash('sha256').update(leaf.raw).digest('base64url')));
        assert.equal(bootstrap.searchParams.get('client_id'), request.client_id);
        assert.equal(request.response_uri, `https://verifier.example.com/verification-session/${id}/response`);
        assert.deepEqual(request.dcql_query, query.dcql_query);
        assert.ok(request.nonce);
      }
      console.log(`${mode}: request verified`);
    } finally { docker('rm', '-f', container); }
  }
} finally { rmSync(dir, { recursive: true, force: true }); }
