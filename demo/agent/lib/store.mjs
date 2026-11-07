/**
 * What the agent keeps between commands, under AGENT_HOME (default `.agent`
 * next to the current directory; `/runtime/agent` in the demo stack): its
 * key, its credential, the subject id the credential binds (`subject.id`,
 * what a site links to an account) and its current token. Files are the
 * agent's alone (0600) except the public subject id. Nothing here is ever
 * committed.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { AgentError, generateKey } from './jose.mjs';

export const FILES = {
	key: 'agent-key.jwk',
	credential: 'credential.sd-jwt',
	subject: 'subject.id',
	token: 'token.json',
};

export class Store {
	constructor(home) {
		this.home = home;
	}

	static fromEnv(env = process.env) {
		return new Store(env.AGENT_HOME && env.AGENT_HOME !== '' ? env.AGENT_HOME : '.agent');
	}

	path(name) {
		return join(this.home, FILES[name]);
	}

	has(name) {
		return existsSync(this.path(name));
	}

	read(name) {
		if (!this.has(name)) {
			throw new AgentError(`no ${name} yet (${this.path(name)})`, `no_${name}`);
		}
		return readFileSync(this.path(name), 'utf8');
	}

	write(name, text) {
		// The directory is traversable so that another process (the demo's
		// WP-CLI step) can read subject.id; the key, credential and token stay 0600.
		const mode = name === 'subject' ? 0o644 : 0o600;
		mkdirSync(this.home, { recursive: true, mode: 0o755 });
		writeFileSync(this.path(name), text.endsWith('\n') ? text : `${text}\n`, { mode });
		chmodSync(this.path(name), mode);
	}

	remove(name) {
		if (this.has(name)) {
			unlinkSync(this.path(name));
		}
	}

	/** The agent's private key, generated on first use. */
	key() {
		if (!this.has('key')) {
			this.write('key', JSON.stringify(generateKey(), null, 2));
			return { key: JSON.parse(this.read('key')), created: true };
		}
		const key = JSON.parse(this.read('key'));
		if (key.kty !== 'EC' || key.crv !== 'P-256' || typeof key.d !== 'string') {
			throw new AgentError(`${this.path('key')} is not a P-256 private JWK`, 'malformed');
		}
		return { key, created: false };
	}

	token() {
		const parsed = JSON.parse(this.read('token'));
		if (typeof parsed.token !== 'string') {
			throw new AgentError(`${this.path('token')} holds no token`, 'malformed');
		}
		return parsed;
	}
}
