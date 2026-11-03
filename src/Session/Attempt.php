<?php
/**
 * One login attempt, as read from the attempts table.
 *
 * Two identifiers on purpose:
 * - public_id travels to the browser and is useless without the binding cookie;
 * - correlation_id travels to the verifier and onto the chain, and never reaches the browser.
 * Nobody who watches the chain can tie an attestation to a browser session.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Session;

final class Attempt {

	public function __construct(
		public readonly int $id,
		public readonly string $public_id,
		public readonly string $correlation_id,
		public readonly string $binding_hash,
		public readonly string $nonce,
		public readonly AttemptStatus $status,
		public readonly ?string $verifier_ref,
		public readonly ?string $redirect_to,
		public readonly ?string $subject_commitment,
		public readonly ?string $presentation_hash,
		public readonly int $created_at,
		public readonly int $expires_at,
		public readonly ?int $checked_at,
	) {}

	/**
	 * @param array<string, mixed> $row A row from the attempts table.
	 */
	public static function from_row( array $row ): self {
		$time = static fn ( $v ): ?int => null === $v ? null : (int) strtotime( $v . ' UTC' );

		return new self(
			(int) $row['id'],
			(string) $row['public_id'],
			(string) $row['correlation_id'],
			(string) $row['binding_hash'],
			(string) $row['nonce'],
			AttemptStatus::from( (string) $row['status'] ),
			$row['verifier_ref'] ?? null,
			$row['redirect_to'] ?? null,
			$row['subject_commitment'] ?? null,
			$row['presentation_hash'] ?? null,
			(int) $time( $row['created_at'] ),
			(int) $time( $row['expires_at'] ),
			$time( $row['checked_at'] ?? null ),
		);
	}

	public function is_expired( ?int $now = null ): bool {
		return ( $now ?? time() ) >= $this->expires_at;
	}
}
