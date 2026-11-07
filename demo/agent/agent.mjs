#!/usr/bin/env node
/**
 * blocLabs SSI Login reference agent: logs in to a WordPress site with a
 * Verifiable Credential and no browser, and gets an application token
 * (docs/adr/0007-agent-login.md).
 *
 *   agent.mjs keygen                      make the agent's key (once)
 *   agent.mjs receive <offer>             take the agent credential from an issuer
 *   agent.mjs login <site> [--scope …]    present it, get a token
 *   agent.mjs call <path> [--method …]    call the REST API with the token
 *   agent.mjs logout                      revoke the token
 *   agent.mjs whoami [--json]             what the agent is and holds
 *
 * No dependencies: Node 22's crypto, fetch and util do the work.
 */

import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

import { banner, colours, keyValue, paint, step } from './lib/brand.mjs';
import { login } from './lib/flow.mjs';
import { AgentError, didJwk, thumbprintUri } from './lib/jose.mjs';
import { receive } from './lib/oid4vci.mjs';
import { holderSubjectId, parse, resolve } from './lib/sdjwt.mjs';
import { Store } from './lib/store.mjs';
import { SiteClient, restError } from './lib/wordpress.mjs';

const USAGE = `Usage:
  agent.mjs keygen
  agent.mjs receive <credential offer> [--tx-code <code>] [--proof-key did|jwk]
  agent.mjs login <site URL> [--scope read,content] [--verifier <client id>] [--vp-token-form array|string] [--show-token]
  agent.mjs call <path under /wp-json/> [--method GET|POST|…] [--data <JSON>]
  agent.mjs logout
  agent.mjs whoami

Options: --json (machine-readable output), --quiet. AGENT_HOME names the directory for the key,
the credential and the token (default .agent); NO_COLOR turns colour off.`;

const OPTIONS = {
	json: { type: 'boolean', default: false },
	quiet: { type: 'boolean', default: false },
	help: { type: 'boolean', short: 'h', default: false },
	scope: { type: 'string' },
	verifier: { type: 'string' },
	'vp-token-form': { type: 'string' },
	'show-token': { type: 'boolean', default: false },
	'tx-code': { type: 'string' },
	'proof-key': { type: 'string' },
	method: { type: 'string' },
	data: { type: 'string' },
};

/** The token with its secret part hidden, for a screen. */
export function maskToken(token) {
	return typeof token === 'string' && token.length > 12 ? `${token.slice(0, 9)}…${token.slice(-4)}` : '(token)';
}

/** What `whoami` reports: the key's identifiers and, when held, the credential's. */
export function identity(store) {
	const { key } = store.key();
	const out = {
		did: didJwk(key),
		thumbprint_uri: thumbprintUri(key),
		home: store.home,
		credential: null,
		subject_id: null,
		token: null,
	};
	if (store.has('credential')) {
		const sdJwt = parse(store.read('credential'));
		const { claims } = resolve(sdJwt);
		const { cnf, iss, vct, exp, iat, _sd_alg, ...rest } = claims; // eslint-disable-line no-unused-vars
		out.credential = { issuer: iss ?? null, vct: vct ?? null, expires_at: typeof exp === 'number' ? new Date(exp * 1000).toISOString() : null, claims: rest };
		out.subject_id = holderSubjectId(cnf);
	}
	if (store.has('token')) {
		const saved = store.token();
		out.token = { site: saved.site ?? null, expires_at: saved.expires_at ?? null, scope: saved.scope ?? null, user_id: saved.user_id ?? null, delegated: saved.delegated ?? null };
	}
	return out;
}

export async function main(argv, env = process.env, io = { stdout: process.stdout, stderr: process.stderr }) {
	const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
	const [command, ...rest] = positionals;
	const p = paint(colours(io.stdout, env) && !values.json);
	const say = (line) => {
		if (!values.json && !values.quiet) {
			io.stdout.write(`${line}\n`);
		}
	};
	const log = (line) => say(step(p, line));
	const emit = (object) => io.stdout.write(`${JSON.stringify(object, null, 2)}\n`);

	if (values.help || command === undefined || command === 'help') {
		io.stdout.write(`${USAGE}\n`);
		return 0;
	}
	const store = Store.fromEnv(env);
	say(banner(p));

	switch (command) {
		case 'keygen': {
			const { created } = store.key();
			const me = identity(store);
			log(created ? `key generated in ${store.path('key')}` : `key already exists in ${store.path('key')}`);
			say(keyValue(p, 'did:jwk', me.did));
			say(keyValue(p, 'thumbprint', me.thumbprint_uri));
			if (values.json) {
				emit(me);
			}
			return 0;
		}
		case 'whoami': {
			const me = identity(store);
			if (values.json) {
				emit(me);
				return 0;
			}
			say(keyValue(p, 'did:jwk', me.did));
			say(keyValue(p, 'thumbprint', me.thumbprint_uri));
			if (me.credential === null) {
				say(keyValue(p, 'credential', p.dim('none yet: agent.mjs receive <offer>')));
			} else {
				say(keyValue(p, 'credential', `${me.credential.vct ?? '(no vct)'} from ${me.credential.issuer ?? '(no issuer)'}, until ${me.credential.expires_at ?? '?'}`));
				say(keyValue(p, 'subject id', me.subject_id ?? p.dim('(cnf names neither a JWK nor a DID)')));
				say(keyValue(p, 'claims', JSON.stringify(me.credential.claims)));
			}
			if (me.token !== null) {
				say(keyValue(p, 'token', `for ${me.token.site ?? '?'}, scope ${(me.token.scope ?? []).join(', ')}, until ${me.token.expires_at ?? '?'}`));
			}
			return 0;
		}
		case 'receive': {
			if (rest.length !== 1) {
				throw new AgentError('receive takes the credential offer as its one argument', 'usage');
			}
			const { key } = store.key();
			const proofKey = values['proof-key'] ?? 'did';
			if (proofKey !== 'did' && proofKey !== 'jwk') {
				throw new AgentError('--proof-key is did or jwk', 'usage');
			}
			const got = await receive(rest[0], key, { log, txCode: values['tx-code'], proofKey });
			store.write('credential', got.credential);
			const me = identity(store);
			if (me.subject_id !== null) {
				store.write('subject', me.subject_id);
			} else {
				store.remove('subject');
			}
			log(`credential stored in ${store.path('credential')}`);
			say(keyValue(p, 'type', me.credential?.vct ?? '(no vct)'));
			say(keyValue(p, 'issuer', me.credential?.issuer ?? '(no issuer)'));
			say(keyValue(p, 'subject id', me.subject_id ?? '(cnf names neither a JWK nor a DID)'));
			say(keyValue(p, 'claims', JSON.stringify(me.credential?.claims ?? {})));
			if (values.json) {
				emit(me);
			}
			return 0;
		}
		case 'login': {
			if (rest.length !== 1) {
				throw new AgentError('login takes the site URL as its one argument', 'usage');
			}
			const form = values['vp-token-form'] ?? env.AGENT_VP_TOKEN_FORM ?? 'array';
			if (form !== 'array' && form !== 'string') {
				throw new AgentError('--vp-token-form is array or string', 'usage');
			}
			const { key } = store.key();
			const token = await login({
				site: rest[0],
				scope: scopes(values.scope),
				key,
				credential: store.read('credential'),
				verifier: values.verifier ?? env.AGENT_VERIFIER ?? null,
				vpTokenForm: form,
				log,
			});
			store.write('token', JSON.stringify({ site: new SiteClient(rest[0]).site, ...token }, null, 2));
			if (values.json) {
				emit(values['show-token'] ? token : { ...token, token: maskToken(token.token) });
				return 0;
			}
			say(keyValue(p, 'token', values['show-token'] ? token.token : `${maskToken(token.token)} ${p.dim('(--show-token prints it)')}`));
			say(keyValue(p, 'scope', Array.isArray(token.scope) ? token.scope.join(', ') : String(token.scope)));
			say(keyValue(p, 'expires', String(token.expires_at ?? '?')));
			say(keyValue(p, 'user', `${String(token.user_id ?? '?')}${token.delegated ? ' (delegated: the agent acts for this account)' : ' (the agent\'s own key is linked to this account)'}`));
			say(keyValue(p, 'saved', store.path('token')));
			return 0;
		}
		case 'call': {
			if (rest.length !== 1) {
				throw new AgentError('call takes the path under /wp-json/ as its one argument', 'usage');
			}
			const saved = store.token();
			const site = new SiteClient(saved.site);
			let body;
			if (values.data !== undefined) {
				body = JSON.parse(values.data);
			}
			const answer = await site.call(rest[0], { method: values.method ?? (body === undefined ? 'GET' : 'POST'), token: saved.token, body });
			if (values.json) {
				emit({ status: answer.status, body: answer.json ?? answer.text });
			} else {
				log(`${values.method ?? (body === undefined ? 'GET' : 'POST')} ${rest[0]} → HTTP ${answer.status}${answer.status >= 400 ? ` ${restError(answer)}` : ''}`);
				io.stdout.write(`${answer.json === undefined ? answer.text : JSON.stringify(answer.json, null, 2)}\n`);
			}
			return answer.status < 400 ? 0 : 3;
		}
		case 'logout': {
			const saved = store.token();
			await new SiteClient(saved.site).revoke(saved.token);
			store.remove('token');
			log('token revoked and forgotten');
			if (values.json) {
				emit({ revoked: true });
			}
			return 0;
		}
		default:
			throw new AgentError(`unknown command ${command}\n${USAGE}`, 'usage');
	}
}

function scopes(value) {
	if (value === undefined || value.trim() === '') {
		return ['read'];
	}
	return value.split(',').map((s) => s.trim()).filter((s) => s !== '');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	main(process.argv.slice(2)).then(
		(code) => {
			process.exitCode = code;
		},
		(error) => {
			const code = error instanceof AgentError ? error.code : 'error';
			process.stderr.write(`agent: ${error.message}${code === 'error' ? '' : ` [${code}]`}\n`);
			process.exitCode = error instanceof AgentError && error.code === 'usage' ? 2 : 1;
		},
	);
}
