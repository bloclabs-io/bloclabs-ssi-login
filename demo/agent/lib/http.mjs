/**
 * One small HTTP helper for every service the agent talks to: a timeout, a
 * body cap, JSON when the answer is JSON, and errors that say which service
 * answered what. Nothing personal is ever logged from here.
 */

import { AgentError } from './jose.mjs';

const MAX_BODY_BYTES = 1024 * 1024;

/**
 * @param {string} url
 * @param {{method?: string, headers?: Record<string, string>, body?: string, fetchImpl?: typeof fetch, timeoutMs?: number, who?: string}} options
 * @returns {Promise<{status: number, headers: Headers, text: string, json: unknown}>}
 */
export async function request(url, options = {}) {
	const { fetchImpl = fetch, timeoutMs = 15_000, who = 'the server' } = options;
	let response;
	let text;
	try {
		response = await fetchImpl(url, {
			method: options.method ?? 'GET',
			headers: options.headers ?? {},
			body: options.body,
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});
		const declared = Number(response.headers.get('content-length') ?? '0');
		if (declared > MAX_BODY_BYTES) {
			throw new AgentError(`${who} answered with a body larger than this agent reads`, 'transport');
		}
		text = await response.text();
	} catch (error) {
		if (error instanceof AgentError) {
			throw error;
		}
		throw new AgentError(`${who} is unreachable: ${error.message}`, 'transport');
	}
	if (text.length > MAX_BODY_BYTES) {
		throw new AgentError(`${who} answered with a body larger than this agent reads`, 'transport');
	}
	let json = undefined;
	const type = response.headers.get('content-type') ?? '';
	if (type.includes('json') || /^\s*[[{]/.test(text)) {
		try {
			json = JSON.parse(text);
		} catch {
			json = undefined;
		}
	}
	return { status: response.status, headers: response.headers, text, json };
}

export async function getJson(url, options = {}) {
	const answer = await request(url, { ...options, headers: { accept: 'application/json', ...(options.headers ?? {}) } });
	if (answer.status < 200 || answer.status >= 300) {
		throw new AgentError(`${options.who ?? 'the server'} answered HTTP ${answer.status} for ${describe(url)}`, 'http_' + answer.status);
	}
	if (answer.json === undefined || answer.json === null || typeof answer.json !== 'object') {
		throw new AgentError(`${options.who ?? 'the server'} did not answer JSON for ${describe(url)}`, 'malformed');
	}
	return answer.json;
}

export function postJson(url, body, options = {}) {
	return request(url, {
		...options,
		method: 'POST',
		headers: { 'content-type': 'application/json', accept: 'application/json', ...(options.headers ?? {}) },
		body: JSON.stringify(body),
	});
}

export function postForm(url, fields, options = {}) {
	const body = new URLSearchParams();
	for (const [name, value] of Object.entries(fields)) {
		if (value !== undefined && value !== null) {
			body.set(name, String(value));
		}
	}
	return request(url, {
		...options,
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...(options.headers ?? {}) },
		body: body.toString(),
	});
}

/** A URL without its query string, for messages: query strings carry ids and codes. */
export function describe(url) {
	try {
		const parsed = new URL(url);
		return `${parsed.origin}${parsed.pathname}`;
	} catch {
		return '(invalid URL)';
	}
}

export function isRecord(value) {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Absolute http(s) URL, with no trailing slash, or an error naming the field. */
export function httpUrl(value, name) {
	if (typeof value !== 'string') {
		throw new AgentError(`${name} must be a URL`, 'malformed');
	}
	let parsed;
	try {
		parsed = new URL(value);
	} catch {
		throw new AgentError(`${name} is not a URL`, 'malformed');
	}
	if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
		throw new AgentError(`${name} must be http(s)`, 'malformed');
	}
	return value.replace(/\/+$/, '');
}
