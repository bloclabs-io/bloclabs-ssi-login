<?php
/**
 * A verifier's on-chain decision about one login attempt, as read from FireFly.
 *
 * It carries commitments, never claims: the chain records that a decision
 * was made and binds it to what the verifier will later hand WordPress,
 * without putting anything personal on the ledger.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

final class Attestation {

	public const RESULT_VERIFIED = 1;
	public const RESULT_REJECTED = 2;

	public function __construct(
		public readonly string $correlation_id,
		public readonly int $result,
		public readonly ?string $subject_commitment,
		public readonly ?string $presentation_hash,
		public readonly string $event_id,
		public readonly ?string $tx_ref,
	) {}

	public function is_verified(): bool {
		return self::RESULT_VERIFIED === $this->result;
	}

	/**
	 * The subject commitment a verifier must emit:
	 * sha256(correlation_id || ":" || blinding_secret || ":" || subject_id).
	 *
	 * The correlation id is public (it is a topic of the same event), so on its
	 * own it would let anyone test a guessed subject id against the chain. The
	 * blinding secret is random per attempt and known to WordPress and the
	 * bridge only, so the same person's logins cannot be linked, and a guess
	 * cannot be checked, by reading the chain (#25).
	 */
	public static function subject_commitment( string $correlation_id, string $blinding_secret, string $subject_id ): string {
		return hash( 'sha256', strtolower( $correlation_id ) . ':' . $blinding_secret . ':' . $subject_id );
	}
}
