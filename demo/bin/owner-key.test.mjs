/**
 * The registry owner must not be a key the bridge can ask FireFly to use
 * after setup. These checks run without Docker.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, cpSync, existsSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { demoSigningPlan } from './deploy.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const walletScript = join(here, 'signer-wallet.sh');
const entrypoint = join(here, 'signer-entrypoint.sh');

function run(args, cwd) {
	const result = spawnSync('sh', [walletScript, ...args], { cwd, encoding: 'utf8' });
	return result;
}

function generate() {
	const dir = mkdtempSync(join(tmpdir(), 'demo-owner-'));
	const env = {
		...process.env,
		DEMO_RUNTIME: join(dir, 'runtime'),
		DEMO_SIGNER: join(dir, 'signer'),
		DEMO_REGISTRY_OWNER: join(dir, 'owner'),
	};
	const result = spawnSync(process.execPath, [join(here, 'init-keys.mjs')], { env, encoding: 'utf8' });
	assert.equal(result.status, 0, result.stderr || result.stdout);
	return dir;
}

function address(dir, name) {
	return readFileSync(join(dir, 'runtime', name), 'utf8').replace(/\s/g, '');
}

function keystoreName(addressValue) {
	return addressValue.replace(/^0x/i, '').toLowerCase();
}

test('the generated registry owner is not the bridge signing key', () => {
	const dir = generate();
	try {
		const signer = address(dir, 'signer.address');
		const owner = address(dir, 'registry-owner.address');
		assert.notEqual(signer.toLowerCase(), owner.toLowerCase());
		const signerFiles = readdirSync(join(dir, 'signer', 'keystore'));
		assert.ok(signerFiles.includes(keystoreName(signer)));
		assert.equal(signerFiles.includes(keystoreName(owner)), false);
		assert.equal(existsSync(join(dir, 'signer', 'registry-owner.password')), false);
		assert.ok(existsSync(join(dir, 'owner', 'keystore', keystoreName(owner))));
		const genesis = JSON.parse(readFileSync(join(dir, 'runtime', 'genesis.json'), 'utf8'));
		assert.ok(genesis.alloc[keystoreName(signer)]);
		assert.ok(genesis.alloc[keystoreName(owner)]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('only the registry owner can deploy the registry and call setIssuer', () => {
	const signer = '0x1111111111111111111111111111111111111111';
	const owner = '0x2222222222222222222222222222222222222222';
	const plan = demoSigningPlan(signer, owner);
	assert.equal(plan.attestor.key, signer);
	assert.deepEqual(plan.attestor.input, [signer]);
	assert.equal(plan.registry.key, owner);
	assert.deepEqual(plan.registry.input, []);
	assert.deepEqual(plan.setIssuer('did:jwk:demo', 'http://issuer.demo/openid4vci/member'), {
		key: owner,
		input: {
			issuer: 'did:jwk:demo',
			vct: 'http://issuer.demo/openid4vci/member',
			trusted: true,
		},
	});
	assert.throws(() => demoSigningPlan(signer, signer), /registry owner must not be the bridge signing key/);
	assert.throws(() => demoSigningPlan(signer, signer.toUpperCase()), /registry owner must not be the bridge signing key/);
});

test('a stale owner key in the signer directory is removed and is not copied into a new wallet', () => {
	const dir = generate();
	try {
		const signer = address(dir, 'signer.address');
		const owner = address(dir, 'registry-owner.address');
		const ownerFile = keystoreName(owner);
		const signerDir = join(dir, 'signer');
		cpSync(join(dir, 'owner', 'keystore', ownerFile), join(signerDir, 'keystore', ownerFile));
		cpSync(join(dir, 'owner', 'keystore', `${ownerFile}.toml`), join(signerDir, 'keystore', `${ownerFile}.toml`));
		cpSync(join(dir, 'owner', 'password'), join(signerDir, 'registry-owner.password'));
		assert.ok(existsSync(join(signerDir, 'keystore', ownerFile)));

		const stripped = run(['strip', '--dir', signerDir, '--address-file', join(dir, 'runtime', 'registry-owner.address')]);
		assert.equal(stripped.status, 0, stripped.stderr);
		assert.equal(existsSync(join(signerDir, 'keystore', ownerFile)), false);
		assert.equal(existsSync(join(signerDir, 'keystore', `${ownerFile}.toml`)), false);
		assert.equal(existsSync(join(signerDir, 'registry-owner.password')), false);
		assert.ok(existsSync(join(signerDir, 'keystore', keystoreName(signer))));

		cpSync(join(dir, 'owner', 'keystore', ownerFile), join(signerDir, 'keystore', ownerFile));
		cpSync(join(dir, 'owner', 'keystore', `${ownerFile}.toml`), join(signerDir, 'keystore', `${ownerFile}.toml`));
		writeFileSync(join(signerDir, 'registry-owner.password'), 'stale');
		const dest = join(dir, 'live');
		const prepared = run([
			'prepare',
			'--attest', signerDir,
			'--dest', dest,
			'--signer-file', join(dir, 'runtime', 'signer.address'),
			'--owner-file', join(dir, 'runtime', 'registry-owner.address'),
		]);
		assert.equal(prepared.status, 0, prepared.stderr);
		const live = readdirSync(join(dest, 'keystore'));
		assert.deepEqual(live.sort(), [keystoreName(signer), `${keystoreName(signer)}.toml`].sort());
		assert.equal(existsSync(join(dest, 'registry-owner.password')), false);
		assert.equal(existsSync(join(dest, 'password')), true);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('the signer drops an owner key when setup stops refreshing the heartbeat', () => {
	const fresh = run(['heartbeat-stale', '100', '90']);
	assert.equal(fresh.status, 1);
	const stale = run(['heartbeat-stale', '100', '70']);
	assert.equal(stale.status, 0);
	const missing = run(['heartbeat-stale', '100', '']);
	assert.equal(missing.status, 0);
	const source = readFileSync(entrypoint, 'utf8');
	assert.match(source, /heartbeat-stale "\$\{now\}" "\$\{beat\}"/);
	assert.match(source, /signer-wallet\.sh prepare/);
	assert.doesNotMatch(source, /\/registry-owner\//);
});
