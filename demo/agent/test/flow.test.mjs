import test from 'node:test';
import assert from 'node:assert/strict';

import { login } from '../lib/flow.mjs';
import { generateKey, didJwkKeyId } from '../lib/jose.mjs';
import { SiteClient } from '../lib/wordpress.mjs';
import { ACTS_FOR, AGENT_PROFILE, issueSdJwt, selfSigned, startVerifier, startWordPress } from './support.mjs';

const key = generateKey();
const quiet = () => {};
const noSleep = () => Promise.resolve();

function credentialFor(overrides = {}) {
	return issueSdJwt({ claims: { ...AGENT_PROFILE.credentialData, ...overrides }, sd: AGENT_PROFILE.sd, holder: { kid: didJwkKeyId(key) } });
}

test('an agent logs in without a browser: initiate, present, poll, token', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier, { pendingPolls: 2 });
	try {
		const log = [];
		const token = await login({ site: wordpress.url, scope: ['read', 'content'], key, credential: credentialFor(), log: (line) => log.push(line), sleep: noSleep });

		assert.match(token.token, /^bssi_/);
		assert.equal(token.token_type, 'Bearer');
		assert.deepEqual(token.scope, ['read', 'content']);
		assert.equal(token.user_id, 7);
		assert.equal(token.delegated, false, 'an empty acts_for is the agent\'s own account');

		const paths = wordpress.state.calls.map((c) => `${c.method} ${c.path}`);
		assert.deepEqual(paths, [
			'POST /wp-json/bloclabs-ssi/v1/agent/initiate',
			'POST /wp-json/bloclabs-ssi/v1/agent/token',
			'POST /wp-json/bloclabs-ssi/v1/agent/token',
			'POST /wp-json/bloclabs-ssi/v1/agent/token',
		], 'two pending answers, then the token');
		assert.ok(wordpress.state.calls.slice(1).every((c) => typeof c.attemptHeader === 'string' && c.attemptHeader.length > 20), 'the attempt secret travels in the header, never in the body');
		assert.equal(log.at(-1), 'token issued');

		const [session] = [...verifier.state.sessions.values()];
		assert.equal(session.received.kb.aud, session.request.client_id);
		assert.deepEqual(session.received.disclosed.sort(), ['acts_for', 'agent', 'scope']);
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('a delegated credential logs the agent in as the principal, with the credential\'s scope as the ceiling', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier);
	try {
		const token = await login({ site: wordpress.url, scope: ['read', 'content', 'settings'], key, credential: credentialFor({ acts_for: ACTS_FOR, scope: ['read'] }), log: quiet, sleep: noSleep });
		assert.equal(token.delegated, true);
		assert.deepEqual(token.scope, ['read'], 'WordPress intersects the request with the credential and the site');
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('the token is a Bearer credential for the REST API, bounded by scope, and can be revoked', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier);
	try {
		const token = await login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), log: quiet, sleep: noSleep });
		const site = new SiteClient(wordpress.url);

		const me = await site.call('wp/v2/users/me', { token: token.token });
		assert.equal(me.status, 200);
		assert.equal(me.json.id, 7);

		const settings = await site.call('wp/v2/settings', { token: token.token });
		assert.equal(settings.status, 403, 'no scope reaches the settings');

		const post = await site.call('wp/v2/posts', { token: token.token, method: 'POST', body: { title: 'x' } });
		assert.equal(post.status, 403, 'read scope cannot write content');

		await site.revoke(token.token);
		const after = await site.call('wp/v2/users/me', { token: token.token });
		assert.equal(after.status, 401, 'a revoked token is refused');
		await assert.rejects(site.revoke(token.token), /did not revoke the token/);
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('with agent login off, WordPress has no agent routes, and the agent says so', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier, { agentLoginOff: true });
	try {
		await assert.rejects(login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), log: quiet, sleep: noSleep }), (error) => error.code === 'agent_login_off' && /agent login is off/.test(error.message));
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('the agent presents only to the verifier WordPress named: a pinned client id is enforced (threat A2)', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier);
	try {
		await assert.rejects(login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), verifier: 'x509_san_dns:verifier.demo', log: quiet, sleep: noSleep }), /not the pinned x509_san_dns:verifier.demo/);
		assert.equal([...verifier.state.sessions.values()][0].received, null, 'nothing was presented');
		assert.equal(wordpress.state.calls.filter((c) => c.path.endsWith('/agent/token')).length, 0, 'and no token was asked for');
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

const cert = selfSigned('verifier.test');

test('a verifier with a certified identity signs its request, and the agent checks the certificate against the pin', { skip: cert === null && 'openssl is not installed' }, async () => {
	const verifier = await startVerifier({ signed: cert, clientId: 'x509_san_dns:verifier.test', responseUriHost: 'verifier.test' });
	const wordpress = await startWordPress(verifier);
	try {
		// The response_uri names verifier.test; route that host to the loopback verifier for this test.
		const fetchImpl = (url, init) => fetch(String(url).replace('http://verifier.test/', `${verifier.url}/`), init);
		const log = [];
		const token = await login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), verifier: 'x509_san_dns:verifier.test', fetchImpl, log: (line) => log.push(line), sleep: noSleep });
		assert.match(token.token, /^bssi_/);
		assert.ok(log.some((line) => line.includes('signed request, certificate checked')));
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('a credential of another type, or one missing a requested claim, is not presented', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier);
	try {
		const otherType = issueSdJwt({ claims: { email: 'ada@example.com' }, sd: ['email'], holder: { kid: didJwkKeyId(key) }, vct: 'http://issuer.test/openid4vci/member' });
		await assert.rejects(login({ site: wordpress.url, scope: ['read'], key, credential: otherType, log: quiet, sleep: noSleep }), /asks for no SD-JWT VC credential this agent holds/);

		const partial = issueSdJwt({ claims: { acts_for: '', scope: ['read'] }, sd: ['acts_for', 'scope'], holder: { kid: didJwkKeyId(key) } });
		await assert.rejects(login({ site: wordpress.url, scope: ['read'], key, credential: partial, log: quiet, sleep: noSleep }), (error) => error.code === 'missing_claim');
		assert.ok([...verifier.state.sessions.values()].every((s) => s.received === null));
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('the vp_token can be sent in the older string form for verifiers that read it', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier);
	try {
		await login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), vpTokenForm: 'string', log: quiet, sleep: noSleep });
		assert.equal([...verifier.state.sessions.values()][0].received.form, 'string');
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('a consumed attempt answers 409 already used, which ends the poll instead of continuing it', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier, { pendingPolls: 0 });
	try {
		const site = new SiteClient(wordpress.url);
		const token = await login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), log: quiet, sleep: noSleep });
		const [attemptId, attempt] = [...wordpress.state.attempts.entries()][0];
		assert.equal(attempt.status, 'consumed');
		await assert.rejects(site.token(attemptId, attempt.secret), /did not issue a token: .*already used/);
		assert.match(token.token, /^bssi_/);
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});

test('the poll gives up when the attempt expires before the chain speaks', async () => {
	const verifier = await startVerifier();
	const wordpress = await startWordPress(verifier, { pendingPolls: 1_000_000 });
	try {
		let polls = 0;
		const fetchImpl = async (url, init) => {
			const answer = await fetch(url, init);
			if (String(url).endsWith('/agent/initiate')) {
				const body = await answer.json();
				return new Response(JSON.stringify({ ...body, expires_in: 0.05, poll_after: 0.01 }), { status: 201, headers: { 'content-type': 'application/json' } });
			}
			if (String(url).endsWith('/agent/token')) {
				polls += 1;
			}
			return answer;
		};
		await assert.rejects(login({ site: wordpress.url, scope: ['read'], key, credential: credentialFor(), fetchImpl, log: quiet }), (error) => error.code === 'timeout');
		assert.ok(polls >= 1 && polls < 50, `polled ${polls} times inside a 50 ms window`);
	} finally {
		await wordpress.close();
		await verifier.close();
	}
});
