<?php
/**
 * What the verifier verified, fetched only after the chain attested it.
 *
 * WordPress binds only the subject and presentation hash to the on-chain
 * commitments. Issuer and claims are authenticated bridge HTTP data; WordPress
 * does not recompute the presentation hash from them or attest them separately.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

use BlocLabs\SsiLogin\FireFly\ContractEventDecoder;

final class PresentationResult {

	/**
	 * @param string               $subject_id        Stable holder identifier (a DID, or issuer + sub).
	 * @param string               $presentation_hash SHA-256 of the canonical JSON of the parsed vp_token, 64 lowercase hex characters.
	 * @param array<string, mixed> $claims            Disclosed claims (only what the query asked for).
	 */
	public function __construct(
		public readonly string $subject_id,
		public readonly ?string $issuer,
		public readonly string $presentation_hash,
		public readonly array $claims,
	) {}

	/**
	 * @param array<string, mixed> $data
	 */
	public static function from_array( array $data ): self {
		$subject = $data['subject_id'] ?? null;
		if ( ! is_string( $subject ) || '' === $subject ) {
			throw VerifierException::unusable( 'The verifier returned a result without a subject.' );
		}

		// The same normalisation as the on-chain value gets, so a "0x" prefix or upper case cannot read as a mismatch.
		$hash = ContractEventDecoder::hex32( $data['presentation_hash'] ?? null );
		if ( null === $hash ) {
			throw VerifierException::unusable( 'The verifier returned a result without a usable presentation hash.' );
		}

		return new self(
			$subject,
			isset( $data['issuer'] ) && is_string( $data['issuer'] ) ? $data['issuer'] : null,
			$hash,
			isset( $data['claims'] ) && is_array( $data['claims'] ) ? $data['claims'] : array(),
		);
	}
}
