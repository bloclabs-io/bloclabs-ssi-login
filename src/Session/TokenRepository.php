<?php
/**
 * Per-site storage of hashed agent tokens and their attestation audit trail.
 *
 * Issuance and authentication are separate: reads include expired/revoked rows
 * for audit, and the caller must enforce expiry, revocation and user permissions.
 * This repository never accepts or stores the bearer secret.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- authentication must see revocation immediately; no cache.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Session;

use BlocLabs\SsiLogin\Database\Schema;

final class TokenRepository {

	/**
	 * Stores an issuance row, with UTC SQL dates and scope as a JSON list.
	 * The issuer owns secret generation and passes only its SHA-256 hash.
	 *
	 * @param array<string, mixed> $row The columns described by ADR 0007, section 4.
	 * @return bool False on an invalid row, duplicate token/attestation, or database failure.
	 */
	public function store( array $row ): bool {
		global $wpdb;
		foreach ( array( 'token_hash', 'agent_subject_hash', 'correlation_id' ) as $hash ) {
			if ( ! is_string( $row[ $hash ] ?? null ) || 1 !== preg_match( '/\A[0-9a-f]{64}\z/', $row[ $hash ] ) ) {
				return false;
			}
		}
		if ( ! is_string( $row['scope'] ?? null ) ) {
			return false;
		}
		$scope = json_decode( $row['scope'], true );
		if ( ! is_array( $scope ) || ! array_is_list( $scope ) || array() === $scope
			|| count( array_filter( $scope, 'is_string' ) ) !== count( $scope ) ) {
			return false;
		}
		$required = array( 'user_id', 'delegated', 'agent_label', 'created_at', 'expires_at' );
		foreach ( $required as $column ) {
			if ( ! isset( $row[ $column ] ) ) {
				return false;
			}
		}
		if ( (int) $row['user_id'] <= 0 || ! in_array( $row['delegated'], array( 0, 1, false, true ), true ) ) {
			return false;
		}

		// An allowlist prevents callers from persisting a secret or overriding lifecycle fields.
		$columns = array_merge(
			$required,
			array( 'token_hash', 'agent_subject_hash', 'correlation_id', 'issuer', 'scope', 'tx_ref', 'firefly_event_id' )
		);
		$data    = array_intersect_key( $row, array_flip( $columns ) );
		return 1 === $wpdb->insert( Schema::tokens_table(), $data );
	}

	/** @return array<string, mixed>|null Raw storage row, including its lifecycle timestamps. */
	public function find( string $token_hash ): ?array {
		global $wpdb;
		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM %i WHERE token_hash = %s', Schema::tokens_table(), $token_hash ),
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	/** @return list<array<string, mixed>> Display/audit fields only; no token or subject hashes. */
	public function for_user( int $user_id ): array {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, delegated, agent_label, issuer, scope, correlation_id, tx_ref, firefly_event_id, created_at, expires_at, last_used_at, revoked_at FROM %i WHERE user_id = %d ORDER BY id',
				Schema::tokens_table(),
				$user_id
			),
			ARRAY_A
		);
	}

	/** Records use at most once per minute, even for concurrent requests. */
	public function touch( string $token_hash, ?int $now = null ): bool {
		global $wpdb;
		$now   = $now ?? time();
		$stamp = gmdate( 'Y-m-d H:i:s', $now );
		return 1 === $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET last_used_at = %s WHERE token_hash = %s AND revoked_at IS NULL AND expires_at > %s AND (last_used_at IS NULL OR last_used_at <= %s)',
				Schema::tokens_table(),
				$stamp,
				$token_hash,
				$stamp,
				gmdate( 'Y-m-d H:i:s', $now - MINUTE_IN_SECONDS )
			)
		);
	}

	/** Revocation is one-way; a repeated call preserves the original audit timestamp. */
	public function revoke( string $token_hash ): bool {
		global $wpdb;
		return 1 === $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET revoked_at = %s WHERE token_hash = %s AND revoked_at IS NULL',
				Schema::tokens_table(),
				gmdate( 'Y-m-d H:i:s' ),
				$token_hash
			)
		);
	}

	/**
	 * Deletes rows only after expiry or revocation plus the audit retention period.
	 * A negative filter value cannot make a live token eligible for deletion.
	 *
	 * @return int Rows deleted.
	 */
	public function purge( int $keep_seconds ): int {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 0, $keep_seconds ) );
		return (int) $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE expires_at <= %s OR revoked_at <= %s',
				Schema::tokens_table(),
				$cutoff,
				$cutoff
			)
		);
	}
}
