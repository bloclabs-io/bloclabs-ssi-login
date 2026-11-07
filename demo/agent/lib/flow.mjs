/**
 * The agent's login, end to end (ADR 0007 §2), with no browser anywhere:
 *
 * 1. open an attempt at WordPress (`POST /agent/initiate`) and get the wallet URL;
 * 2. fetch the request object it points to and check the verifier's identity;
 * 3. pick the disclosures the DCQL query asks for and sign the key-binding JWT;
 * 4. post the presentation to the verifier;
 * 5. poll `POST /agent/token` until the chain has spoken and WordPress issues
 *    the token, once.
 *
 * The wallet URL used in step 2 is always the one step 1 returned: this
 * function has no other input for it (threat A2).
 */

import { AgentError } from './jose.mjs';
import { checkVerifier, chooseCredentialQuery, fetchRequest, respond, vpToken } from './oid4vp.mjs';
import { parse, present, select } from './sdjwt.mjs';
import { SiteClient } from './wordpress.mjs';

const MAX_POLL_SECONDS = 600;

/**
 * @param {{site: string, scope: string[], key: Record<string, string>, credential: string, verifier?: string | null,
 *          vpTokenForm?: 'array' | 'string', fetchImpl?: typeof fetch, log?: (line: string) => void,
 *          sleep?: (ms: number) => Promise<void>}} input
 * @returns {Promise<Record<string, unknown>>} The token answer: token, token_type, expires_at, scope, user_id, delegated.
 */
export async function login(input) {
	const { log = () => {}, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = input;
	const site = new SiteClient(input.site, { fetchImpl: input.fetchImpl });
	const sdJwt = parse(input.credential);
	const vct = typeof sdJwt.payload.vct === 'string' ? sdJwt.payload.vct : null;

	const opened = await site.initiate(input.scope);
	log(`attempt opened at ${site.site}, scope ${input.scope.join(', ') || '(default)'}`);

	const { request, leaf, clientId } = await fetchRequest(opened.walletUrl, { fetchImpl: input.fetchImpl });
	const verifier = checkVerifier(request, { clientId, leaf, expected: input.verifier ?? null });
	log(`verifier ${verifier.clientId}${leaf === null ? ' (unsigned request)' : ' (signed request, certificate checked)'}`);

	const query = chooseCredentialQuery(request.dcql_query, vct);
	const disclosures = select(sdJwt, query.paths);
	const presentation = present(sdJwt, disclosures, { aud: verifier.clientId, nonce: verifier.nonce }, input.key);
	log(`presenting ${disclosures.length} of ${sdJwt.disclosures.length} disclosures for query ${query.id}`);

	await respond(verifier.responseUri, vpToken(query.id, presentation, input.vpTokenForm ?? 'array'), verifier.state, { fetchImpl: input.fetchImpl });
	log('presentation accepted by the verifier; waiting for the chain');

	const deadline = Date.now() + Math.min(opened.expiresIn, MAX_POLL_SECONDS) * 1000;
	let wait = opened.pollAfter;
	for (;;) {
		const answer = await site.token(opened.attempt, opened.attemptSecret);
		if (!answer.pending) {
			log('token issued');
			return answer.token;
		}
		if (Date.now() >= deadline) {
			throw new AgentError('the attempt expired before WordPress saw the attestation', 'timeout');
		}
		wait = answer.pollAfter ?? wait;
		await sleep(wait * 1000);
	}
}

export { SiteClient };
