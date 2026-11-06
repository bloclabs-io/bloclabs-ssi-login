import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { X509Certificate, createHash, createPrivateKey } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import { requestBody, startBridge } from './helpers.js';

it('passes signed_request from bridge configuration to the verifier', async () => {
  const bridge = await startBridge({ VERIFIER_SIGNED_REQUEST: 'true' });
  try {
    assert.equal((await bridge.call('POST', '/v1/presentation-requests', requestBody())).status, 201);
    const core = bridge.verifier.createCalls[0]!['core_flow'] as Record<string, unknown>;
    assert.equal(core['signed_request'], true);
    assert.equal(core['key'], undefined, 'private material stays in the verifier');
  } finally { await bridge.close(); }
});

it('generates private signing config and rejects inconsistent material', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bridge-signing-'));
  try {
    const key = join(dir, 'key.pem');
    const cert = join(dir, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=verifier.example.com',
      '-addext', 'subjectAltName=DNS:verifier.example.com'], { stdio: 'ignore' });
    const leaf = new X509Certificate(readFileSync(cert));
    for (const mode of ['x509_san_dns', 'x509_hash']) {
      const output = join(dir, `${mode}.conf`);
      const args = ['verifier/configure-signing.mjs', '--key', key, '--cert', cert,
        '--url', 'https://verifier.example.com', '--mode', mode, '--output', output];
      execFileSync(process.execPath, args);
      const config = JSON.parse(readFileSync(output, 'utf8'));
      assert.equal(statSync(output).mode & 0o777, 0o600);
      assert.equal(config.clientId, mode + ':' + (mode === 'x509_san_dns' ? 'verifier.example.com'
        : createHash('sha256').update(leaf.raw).digest('base64url')));
      assert.deepEqual(config.x5c, [leaf.raw.toString('base64')]);
      assert.ok(leaf.checkPrivateKey(createPrivateKey({ key: config.key.jwk, format: 'jwk' })));
      assert.equal(spawnSync(process.execPath, args).status, 1, 'refuses to overwrite private config');
    }
    const args = ['verifier/configure-signing.mjs', '--key', key, '--cert', cert, '--output', join(dir, 'bad.conf')];
    const wrongHost = spawnSync(process.execPath, [...args, '--url', 'https://wrong.example.com'], { encoding: 'utf8' });
    assert.equal(wrongHost.status, 1);
    assert.match(wrongHost.stderr, /DNS SAN/);
    execFileSync('openssl', ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key]);
    const wrongKey = spawnSync(process.execPath, [...args, '--url', 'https://verifier.example.com'], { encoding: 'utf8' });
    assert.equal(wrongKey.status, 1);
    assert.match(wrongKey.stderr, /does not match/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
