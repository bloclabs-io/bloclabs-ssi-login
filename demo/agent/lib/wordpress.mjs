/**
 * The three agent routes of the plugin (ADR 0007 §2), under
 * `/wp-json/bloclabs-ssi/v1/`, and a call with the token.
 *
 * The attempt secret travels in the `X-Bloclabs-Ssi-Attempt` header, the token
 * as `Authorization: Bearer`. Neither is ever put in a URL or logged.
 */

import { AgentError } from './jose.mjs';
import { httpUrl, isRecord, postJson, request } from './http.mjs';

export const NAMESPACE = 'bloclabs-ssi/v1';
export const ATTEMPT_HEADER = 'x-bloclabs-ssi-attempt';

/**
 * 409 answers from `/agent/token` that end the attempt rather than ask for
 * another poll (ADR 0007 §2: "afterwards 409 already used").
 */
const TERMINAL_CODES = ['bloclabs_ssi_already_used'];

export class SiteClient {
	/**
	 * @param {string} siteUrl   The WordPress home URL, e.g. https://example.org or http://wordpress.
	 * @param {{fetchImpl?: typeof fetch}} options
	 */
	constructor(siteUrl, options = {}) {
		this.site = httpUrl(siteUrl, 'the site URL');
		this.fetchImpl = options.fetchImpl;
	}

	route(path) {
		return `${this.site}/wp-json/${path.replace(/^\/+/, '')}`;
	}

	/**
	 * `POST /agent/initiate`.
	 *
	 * @param {string[]} scope
	 * @returns {Promise<{attempt: string, attemptSecret: string, walletUrl: string, expiresIn: number, pollAfter: number}>}
	 */
	async initiate(scope) {
		const answer = await postJson(this.route(`${NAMESPACE}/agent/initiate`), { scope }, { fetchImpl: this.fetchImpl, who: 'WordPress' });
		if (answer.status === 404) {
			throw new AgentError('WordPress has no agent routes: agent login is off, or the plugin is older than ADR 0007', 'agent_login_off');
		}
		if (answer.status !== 201 || !isRecord(answer.json)) {
			throw new AgentError(`WordPress refused to open an attempt: ${restError(answer)}`, 'initiate_refused');
		}
		const body = answer.json;
		for (const field of ['attempt', 'attempt_secret', 'wallet_url']) {
			if (typeof body[field] !== 'string' || body[field] === '') {
				throw new AgentError(`WordPress answered without ${field}`, 'malformed');
			}
		}
		return {
			attempt: body.attempt,
			attemptSecret: body.attempt_secret,
			walletUrl: body.wallet_url,
			expiresIn: positive(body.expires_in, 180),
			pollAfter: positive(body.poll_after, 2),
		};
	}

	/**
	 * `POST /agent/token`: 409 while the chain has not spoken, the token once.
	 *
	 * @returns {Promise<{pending: true, pollAfter: number} | {pending: false, token: Record<string, unknown>}>}
	 */
	async token(attempt, attemptSecret) {
		const answer = await postJson(this.route(`${NAMESPACE}/agent/token`), { attempt }, {
			fetchImpl: this.fetchImpl,
			headers: { [ATTEMPT_HEADER]: attemptSecret },
			who: 'WordPress',
		});
		const code = isRecord(answer.json) && typeof answer.json.code === 'string' ? answer.json.code : null;
		if ((answer.status === 409 && !TERMINAL_CODES.includes(code)) || answer.status === 503) {
			const data = isRecord(answer.json) && isRecord(answer.json.data) ? answer.json.data : {};
			return { pending: true, pollAfter: positive(data.poll_after, 2), code };
		}
		if (answer.status !== 200 || !isRecord(answer.json) || typeof answer.json.token !== 'string') {
			throw new AgentError(`WordPress did not issue a token: ${restError(answer)}`, 'token_refused');
		}
		return { pending: false, token: answer.json };
	}

	/** `DELETE /agent/token`: the agent revokes its own token. */
	async revoke(token) {
		const answer = await request(this.route(`${NAMESPACE}/agent/token`), {
			method: 'DELETE',
			headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
			fetchImpl: this.fetchImpl,
			who: 'WordPress',
		});
		if (answer.status < 200 || answer.status >= 300) {
			throw new AgentError(`WordPress did not revoke the token: ${restError(answer)}`, 'revoke_refused');
		}
	}

	/**
	 * Any REST call with the token.
	 *
	 * @param {string} path   Under /wp-json/, e.g. `wp/v2/users/me`.
	 * @param {{method?: string, token: string, body?: unknown}} options
	 */
	async call(path, options) {
		const headers = { authorization: `Bearer ${options.token}`, accept: 'application/json' };
		let body;
		if (options.body !== undefined) {
			headers['content-type'] = 'application/json';
			body = JSON.stringify(options.body);
		}
		return request(this.route(path), { method: options.method ?? 'GET', headers, body, fetchImpl: this.fetchImpl, who: 'WordPress' });
	}
}

function positive(value, fallback) {
	const number = Number(value);
	return Number.isFinite(number) && number > 0 ? number : fallback;
}

/** A WordPress REST error, as its code and message, never its data. */
export function restError(answer) {
	if (isRecord(answer.json) && typeof answer.json.code === 'string') {
		return `HTTP ${answer.status} ${answer.json.code}${typeof answer.json.message === 'string' ? ` (${answer.json.message})` : ''}`;
	}
	return `HTTP ${answer.status}`;
}
