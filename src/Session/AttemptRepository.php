<?php
/**
 * Storage for login attempts.
 *
 * Status changes are compare-and-set updates (`... WHERE id = ? AND status = ?`),
 * so concurrent webhooks, polls and clicks resolve to exactly one winner.
 * Times are stored in UTC.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- a custom table, deliberately uncached: its rows change within seconds.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Session;

use BlocLabs\SsiLogin\Database\Schema;

final class AttemptRepository {

	/**
	 * Opens a new pending attempt with fresh random identifiers.
	 */
	public function open( string $binding_hash, ?string $ip_hash, int $ttl, ?string $redirect_to ): Attempt {
		global $wpdb;

		$now = time();
		$row = array(
			'public_id'      => bin2hex( random_bytes( 16 ) ),
			'correlation_id' => bin2hex( random_bytes( 32 ) ),
			'binding_hash'   => $binding_hash,
			'nonce'          => rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- base64url of random bytes.
			'status'         => AttemptStatus::Pending->value,
			'ip_hash'        => $ip_hash,
			'redirect_to'    => $redirect_to,
			'created_at'     => gmdate( 'Y-m-d H:i:s', $now ),
			'expires_at'     => gmdate( 'Y-m-d H:i:s', $now + $ttl ),
		);

		if ( false === $wpdb->insert( Schema::attempts_table(), $row ) ) {
			throw new \RuntimeException( 'Could not store the login attempt.' );
		}

		return Attempt::from_row( $row + array( 'id' => (int) $wpdb->insert_id ) );
	}

	public function find_by_public_id( string $public_id ): ?Attempt {
		return $this->find_by( 'public_id', $public_id );
	}

	public function find_by_correlation_id( string $correlation_id ): ?Attempt {
		return $this->find_by( 'correlation_id', strtolower( $correlation_id ) );
	}

	/**
	 * Atomically moves an attempt from one status to another.
	 *
	 * @param array<string, scalar|null> $fields Extra columns to write in the same UPDATE.
	 * @return bool True when this call made the change.
	 */
	public function transition( Attempt $attempt, AttemptStatus $to, array $fields = array() ): bool {
		global $wpdb;

		if ( ! $attempt->status->can_transition_to( $to ) ) {
			return false;
		}

		$stamp = gmdate( 'Y-m-d H:i:s' );
		$data  = array( 'status' => $to->value ) + $fields;
		if ( AttemptStatus::Verified === $to || AttemptStatus::Rejected === $to ) {
			$data['attested_at'] = $stamp;
		}
		if ( AttemptStatus::Consumed === $to ) {
			$data['consumed_at'] = $stamp;
		}

		$updated = $wpdb->update(
			Schema::attempts_table(),
			$data,
			array(
				'id'     => $attempt->id,
				'status' => $attempt->status->value,
			)
		);

		return 1 === $updated;
	}

	public function set_verifier_ref( Attempt $attempt, string $ref ): void {
		global $wpdb;
		$wpdb->update( Schema::attempts_table(), array( 'verifier_ref' => $ref ), array( 'id' => $attempt->id ) );
	}

	/**
	 * Claims the right to poll FireFly for this attempt (at most once per interval).
	 */
	public function claim_check( Attempt $attempt, int $interval ): bool {
		global $wpdb;
		$table = Schema::attempts_table();
		$now   = gmdate( 'Y-m-d H:i:s' );
		$limit = gmdate( 'Y-m-d H:i:s', time() - $interval );

		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET checked_at = %s WHERE id = %d AND status = %s AND (checked_at IS NULL OR checked_at <= %s)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$now,
				$attempt->id,
				AttemptStatus::Pending->value,
				$limit
			)
		);

		return 1 === $updated;
	}

	public function count_recent_pending_for_ip( string $ip_hash, int $window ): int {
		global $wpdb;
		$table = Schema::attempts_table();

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE ip_hash = %s AND status = %s AND created_at >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$ip_hash,
				AttemptStatus::Pending->value,
				gmdate( 'Y-m-d H:i:s', time() - $window )
			)
		);
	}

	public function oldest_pending_created_at(): ?int {
		global $wpdb;
		$table = Schema::attempts_table();
		$value = $wpdb->get_var(
			$wpdb->prepare( "SELECT MIN(created_at) FROM {$table} WHERE status = %s", AttemptStatus::Pending->value ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
		return null === $value ? null : (int) strtotime( $value . ' UTC' );
	}

	/**
	 * Expires stale attempts and deletes old ones. Runs from cron.
	 *
	 * @return int Rows deleted.
	 */
	public function purge( int $keep_seconds ): int {
		global $wpdb;
		$table = Schema::attempts_table();
		$now   = gmdate( 'Y-m-d H:i:s' );

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET status = %s WHERE status IN (%s, %s) AND expires_at <= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				AttemptStatus::Expired->value,
				AttemptStatus::Pending->value,
				AttemptStatus::Verified->value,
				$now
			)
		);

		return (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at <= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				gmdate( 'Y-m-d H:i:s', time() - $keep_seconds )
			)
		);
	}

	private function find_by( string $column, string $value ): ?Attempt {
		global $wpdb;
		$table = Schema::attempts_table();
		// $column is one of two literals above, never input.
		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE {$column} = %s LIMIT 1", $value ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);
		return is_array( $row ) ? Attempt::from_row( $row ) : null;
	}
}
