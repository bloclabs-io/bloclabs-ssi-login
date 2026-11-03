<?php
/**
 * What the verifier verified, fetched only after the chain attested it.
 *
 * WordPress checks it against the on-chain commitments before using it, so
 * the verifier's HTTP answer and its on-chain record must agree.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

final class PresentationResult {

	/**
	 * @param string               $subject_id        Stable holder identifier (a DID, or issuer + sub).
	 * @param string               $presentation_hash SHA-256 of the presentation as received, hex.
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
		$hash    = $data['presentation_hash'] ?? null;

		if ( ! is_string( $subject ) || '' === $subject || ! is_string( $hash ) ) {
			throw new VerifierException( 'The verifier returned an incomplete result.' );
		}

		return new self(
			$subject,
			isset( $data['issuer'] ) && is_string( $data['issuer'] ) ? $data['issuer'] : null,
			strtolower( $hash ),
			isset( $data['claims'] ) && is_array( $data['claims'] ) ? $data['claims'] : array(),
		);
	}
}
