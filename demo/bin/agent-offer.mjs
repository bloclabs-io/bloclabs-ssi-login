/**
 * Asks the issuer for an agent credential offer (profile `agent`) and writes
 * it to runtime/agent-offer.url for ./agent.sh. With ACTS_FOR set, the
 * credential names that subject id as the principal the agent acts for
 * (ADR 0007); without it the credential is the agent's own.
 *
 * Talks to the issuer by its Compose name. Run it with `docker compose run`
 * on the demo network, not from the host.
 */

import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const issuer = (process.env.ISSUER_URL || 'http://issuer.demo').replace(/\/$/, '');
const runtime = process.env.DEMO_RUNTIME || '/runtime';

/** A subject id as the bridge derives it: a DID, or a JWK thumbprint URI. */
const SUBJECT_ID = /^(did:[a-z0-9]+:[A-Za-z0-9._:%-]+|urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]+)$/;

/**
 * The management request for one offer. acts_for travels as a per-offer
 * override of the profile's credential data, so the profile stays the
 * agent's own credential.
 *
 * @param {string} actsFor  Empty for the agent's own credential.
 */
export function offerRequest(actsFor) {
	const principal = String(actsFor ?? '').replace(/\r/g, '').trim();
	if (principal !== '' && !SUBJECT_ID.test(principal)) {
		throw new Error('ACTS_FOR must be a DID (did:jwk:…, did:key:…) or a JWK thumbprint URI, as the wallet or agent.mjs whoami prints it');
	}
	const request = { profileId: 'agent', authMethod: 'PRE_AUTHORIZED', expiresInSeconds: 3600 };
	if (principal !== '') {
		request.runtimeOverrides = { credentialData: { acts_for: principal } };
	}
	return request;
}

async function main() {
	const request = offerRequest(process.env.ACTS_FOR || '');
	let last = 'no response';
	for (let attempt = 1; attempt <= 30; attempt += 1) {
		try {
			const response = await fetch(`${issuer}/issuer2/credential-offers`, {
				method: 'POST',
				headers: { 'content-type': 'application/json', accept: 'application/json' },
				body: JSON.stringify(request),
				signal: AbortSignal.timeout(30000),
			});
			const text = await response.text();
			if (response.ok) {
				const url = JSON.parse(text)?.credentialOffer;
				if (typeof url !== 'string' || url === '') {
					throw new Error(`the issuer returned no credential offer: ${text}`);
				}
				writeFileSync(`${runtime}/agent-offer.url`, `${url}\n`, { mode: 0o644 });
				process.stdout.write(`agent offer ${url}\n`);
				return;
			}
			last = `${response.status} ${text}`;
			if (response.status < 500) {
				throw new Error(`the issuer refused the offer request: ${last}`);
			}
		} catch (error) {
			if (/refused|returned no/.test(error.message)) {
				throw error;
			}
			last = error.message;
		}
		await new Promise((resolve) => setTimeout(resolve, 2000));
	}
	throw new Error(`${issuer} did not answer: ${last}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	await main();
}
