import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { AGENT_PROFILE, startIssuer, startVerifier, startWordPress } from './support.mjs';

const AGENT = fileURLToPath(new URL('../agent.mjs', import.meta.url));

function run(args, env, input) {
	return new Promise((resolve) => {
		const child = spawn(process.execPath, [AGENT, ...args], { env: { ...process.env, NO_COLOR: '1', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
		let stdout = '';
		let stderr = '';
		child.stdout.on('data', (c) => (stdout += c));
		child.stderr.on('data', (c) => (stderr += c));
		child.on('close', (code) => resolve({ code, stdout, stderr }));
		child.stdin.end(input ?? '');
	});
}

test('the CLI takes an agent from no key to a revoked token, with its state in AGENT_HOME', async () => {
	const home = mkdtempSync(join(tmpdir(), 'agent-home-'));
	const issuer = await startIssuer({ profiles: { agent: AGENT_PROFILE } });
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier);
	const env = { AGENT_HOME: home };
	try {
		let r = await run(['keygen'], env);
		assert.equal(r.code, 0, r.stderr);
		assert.match(r.stdout, /blocLabs · SSI Login agent/);
		assert.match(r.stdout, /did:jwk:/);
		assert.equal((statSync(join(home, 'agent-key.jwk')).mode & 0o777).toString(8), '600', 'the key file is private to the agent');

		r = await run(['keygen'], env);
		assert.equal(r.code, 0);
		assert.match(r.stdout, /key already exists/, 'a second keygen keeps the key');

		r = await run(['keygen', '--json'], env);
		assert.equal(r.code, 0);
		assert.doesNotMatch(r.stdout, /blocLabs/, '--json prints JSON and nothing else');
		assert.equal(JSON.parse(r.stdout).did, JSON.parse(r.stdout).did);

		r = await run(['whoami', '--json'], env);
		assert.equal(r.code, 0, r.stderr);
		const me = JSON.parse(r.stdout);
		assert.match(me.did, /^did:jwk:/);
		assert.match(me.thumbprint_uri, /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:/);
		assert.equal(me.credential, null);

		const offer = await fetch(`${issuer.url}/issuer2/credential-offers`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profileId: 'agent', authMethod: 'PRE_AUTHORIZED' }) }).then((a) => a.json());
		r = await run(['receive', offer.credentialOffer], env);
		assert.equal(r.code, 0, r.stderr);
		assert.match(r.stdout, /credential stored/);
		assert.match(r.stdout, /subject id\s+did:jwk:/);
		assert.ok(existsSync(join(home, 'credential.sd-jwt')));
		assert.match(readFileSync(join(home, 'subject.id'), 'utf8'), /^did:jwk:[A-Za-z0-9_-]+\n$/, 'the subject id is written for the operator to link');

		r = await run(['whoami', '--json'], env);
		const held = JSON.parse(r.stdout);
		assert.equal(held.credential.vct, AGENT_PROFILE.vct);
		assert.match(held.credential.issuer, /^did:jwk:/, 'the SD-JWT names its issuer by DID');
		assert.deepEqual(held.credential.claims.scope, ['read', 'content']);
		assert.equal(held.subject_id, me.did, 'the subject id is the did:jwk the credential was bound to');

		r = await run(['login', wordpress.url, '--scope', 'read,content', '--json'], env);
		assert.equal(r.code, 0, r.stderr);
		const token = JSON.parse(r.stdout);
		assert.match(token.token, /^bssi_[^…]{4}…[^…]{4}$/, 'the token is masked unless --show-token');
		assert.deepEqual(token.scope, ['read', 'content']);
		const saved = JSON.parse(readFileSync(join(home, 'token.json'), 'utf8'));
		assert.match(saved.token, /^bssi_/);
		assert.equal(saved.site, wordpress.url);
		assert.equal((statSync(join(home, 'token.json')).mode & 0o777).toString(8), '600');

		r = await run(['call', 'wp/v2/users/me', '--json'], env);
		assert.equal(r.code, 0, r.stderr);
		assert.equal(JSON.parse(r.stdout).body.id, 7);

		r = await run(['call', 'wp/v2/posts', '--data', '{"title":"Nightly report"}'], env);
		assert.equal(r.code, 0, r.stderr);
		assert.match(r.stdout, /POST wp\/v2\/posts → HTTP 201/);

		r = await run(['call', 'wp/v2/settings'], env);
		assert.equal(r.code, 3, 'a refused call exits 3');
		assert.match(r.stdout, /HTTP 403/);

		r = await run(['logout'], env);
		assert.equal(r.code, 0, r.stderr);
		assert.match(r.stdout, /token revoked and forgotten/);
		assert.ok(!existsSync(join(home, 'token.json')));
		assert.equal(wordpress.state.tokens.size, 0);

		r = await run(['call', 'wp/v2/users/me'], env);
		assert.equal(r.code, 1, 'no token, no call');
		assert.match(r.stderr, /^agent: /);
	} finally {
		await wordpress.close();
		await verifier.close();
		await issuer.close();
		rmSync(home, { recursive: true, force: true });
	}
});

test('usage errors exit 2 and name the problem; help exits 0', async () => {
	const home = mkdtempSync(join(tmpdir(), 'agent-home-'));
	try {
		let r = await run(['help'], {});
		assert.equal(r.code, 0);
		assert.match(r.stdout, /^Usage:/);

		r = await run(['frobnicate'], { AGENT_HOME: home });
		assert.equal(r.code, 2);
		assert.match(r.stderr, /unknown command frobnicate/);

		r = await run(['login'], { AGENT_HOME: home });
		assert.equal(r.code, 2);
		assert.match(r.stderr, /login takes the site URL/);

		r = await run(['login', 'http://127.0.0.1:9', '--vp-token-form', 'xml'], { AGENT_HOME: home });
		assert.equal(r.code, 2);
		assert.match(r.stderr, /--vp-token-form is array or string/);

		r = await run(['receive', 'not-an-offer'], { AGENT_HOME: home });
		assert.equal(r.code, 1);
		assert.match(r.stderr, /neither a URL nor JSON \[malformed\]/);
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
});

test('colour is off when NO_COLOR is set or the output is not a terminal', async () => {
	const home = mkdtempSync(join(tmpdir(), 'agent-home-'));
	try {
		const r = await run(['keygen'], { AGENT_HOME: home });
		assert.doesNotMatch(r.stdout, /\u001b\[/, 'no escape sequences into a pipe');
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
});
