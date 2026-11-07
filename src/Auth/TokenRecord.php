<?php
/**
 * One row of the tokens table, as the bearer filter reads it (ADR 0007 §4).
 *
 * The same columns IssuedToken::to_row() writes; the secret is not among them.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Auth;

final class TokenRecord {

	/**
	 * @param list<string> $scope Scope names granted.
	 */
	public function __construct(
		public readonly int $id,
		public readonly string $token_hash,
		public readonly int $user_id,
		public readonly bool $delegated,
		public readonly array $scope,
		public readonly string $agent_label,
		public readonly int $created_at,
		public readonly int $expires_at,
		public readonly ?int $last_used_at,
		public readonly ?int $revoked_at,
	) {}

	/**
	 * @param array<string, mixed> $row A row from the tokens table.
	 */
	public static function from_row( array $row ): self {
		$time  = static fn ( $v ): ?int => null === $v || '' === $v ? null : (int) strtotime( (string) $v . ' UTC' );
		$scope = json_decode( (string) ( $row['scope'] ?? '[]' ), true );

		return new self(
			(int) ( $row['id'] ?? 0 ),
			(string) $row['token_hash'],
			(int) $row['user_id'],
			! empty( $row['delegated'] ),
			is_array( $scope ) ? array_values( array_filter( $scope, 'is_string' ) ) : array(),
			(string) ( $row['agent_label'] ?? '' ),
			(int) $time( $row['created_at'] ?? null ),
			(int) $time( $row['expires_at'] ?? null ),
			$time( $row['last_used_at'] ?? null ),
			$time( $row['revoked_at'] ?? null ),
		);
	}

	public function is_expired( ?int $now = null ): bool {
		return ( $now ?? time() ) >= $this->expires_at;
	}

	public function is_revoked(): bool {
		return null !== $this->revoked_at;
	}
}
