/**
 * Published demo ports stay on loopback and follow demo/.env.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walletApiPublicUrl } from './init-keys.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const compose = readFileSync(join(here, '..', 'docker-compose.yml'), 'utf8');
const setup = readFileSync(join(here, '..', 'setup.sh'), 'utf8');
const envFile = readFileSync(join(here, '..', '.env'), 'utf8');

test('published ports are loopback and the wallet API URL follows the API port', () => {
	assert.match(compose, /127\.0\.0\.1:\$\{WORDPRESS_PORT:-8080\}:80/);
	assert.match(compose, /127\.0\.0\.1:\$\{WALLET_WEB_PORT:-7106\}:8080/);
	assert.match(compose, /127\.0\.0\.1:\$\{WALLET_API_PORT:-7006\}:7006/);
	assert.match(compose, /WALLET_API2_PUBLIC_URL: http:\/\/127\.0\.0\.1:\$\{WALLET_API_PORT:-7006\}/);
	assert.match(compose, /DEMO_WALLET_API_PUBLIC_URL: http:\/\/127\.0\.0\.1:\$\{WALLET_API_PORT:-7006\}/);
	assert.match(compose, /WORDPRESS_PUBLIC_URL: http:\/\/127\.0\.0\.1:\$\{WORDPRESS_PORT:-8080\}/);
	assert.equal(compose.includes('0.0.0.0:'), false);
	assert.match(envFile, /^WORDPRESS_PORT=8080$/m);
	assert.match(envFile, /^WALLET_WEB_PORT=7106$/m);
	assert.match(envFile, /^WALLET_API_PORT=7006$/m);
	assert.match(setup, /WALLET_API_PORT/);
	assert.match(setup, /http:\/\/127\.0\.0\.1:\$\{WALLET_API_PORT\}/);
});

test('the wallet API public URL is loopback and can change without new keys', () => {
	const previous = process.env.DEMO_WALLET_API_PUBLIC_URL;
	process.env.DEMO_WALLET_API_PUBLIC_URL = 'http://127.0.0.1:7016';
	try {
		assert.equal(walletApiPublicUrl(), 'http://127.0.0.1:7016');
		process.env.DEMO_WALLET_API_PUBLIC_URL = 'http://example.com:7006';
		assert.throws(() => walletApiPublicUrl(), /127\.0\.0\.1/);
	} finally {
		if (previous === undefined) {
			delete process.env.DEMO_WALLET_API_PUBLIC_URL;
		} else {
			process.env.DEMO_WALLET_API_PUBLIC_URL = previous;
		}
	}

	const dir = mkdtempSync(join(tmpdir(), 'demo-ports-'));
	const env = {
		...process.env,
		DEMO_RUNTIME: join(dir, 'runtime'),
		DEMO_SIGNER: join(dir, 'signer'),
		DEMO_REGISTRY_OWNER: join(dir, 'owner'),
		DEMO_WALLET_API_PUBLIC_URL: 'http://127.0.0.1:7006',
	};
	try {
		const first = spawnSync(process.execPath, [join(here, 'init-keys.mjs')], { env, encoding: 'utf8' });
		assert.equal(first.status, 0, first.stderr || first.stdout);
		const signer = readFileSync(join(dir, 'runtime', 'signer.address'), 'utf8');
		assert.match(readFileSync(join(dir, 'runtime', 'wallet-service.conf'), 'utf8'), /http:\/\/127\.0\.0\.1:7006/);
		const second = spawnSync(process.execPath, [join(here, 'init-keys.mjs')], {
			env: { ...env, DEMO_WALLET_API_PUBLIC_URL: 'http://127.0.0.1:7016' },
			encoding: 'utf8',
		});
		assert.equal(second.status, 0, second.stderr || second.stdout);
		assert.match(second.stdout, /already exist/);
		assert.equal(readFileSync(join(dir, 'runtime', 'signer.address'), 'utf8'), signer);
		assert.match(readFileSync(join(dir, 'runtime', 'wallet-service.conf'), 'utf8'), /publicBaseUrl = "http:\/\/127\.0\.0\.1:7016"/);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
