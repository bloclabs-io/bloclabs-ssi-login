<?php
/**
 * The OpenID4VP verifier, seen from WordPress.
 *
 * WordPress never parses a credential. The verifier (a sidecar service)
 * speaks OpenID4VP to wallets, checks signatures, holder binding, issuer
 * trust and revocation, then attests its decision on chain through FireFly.
 * WordPress only asks it to open a request and, after the chain says
 * "verified", to hand over the subject it verified.
 *
 * The contract is docs/BRIDGE-API.md. Plug in another verifier with the
 * `bloclabs_ssi_verifier_client` filter.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

interface VerifierClient {

	/**
	 * Opens a presentation request for one login attempt.
	 *
	 * @throws VerifierException
	 */
	public function create_request( PresentationRequest $request ): PresentationOffer;

	/**
	 * Returns what the verifier verified for a request it has attested.
	 *
	 * @throws VerifierException
	 */
	public function fetch_result( string $verifier_ref ): PresentationResult;
}
