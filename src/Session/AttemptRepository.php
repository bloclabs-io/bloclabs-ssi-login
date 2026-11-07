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
	 *
	 * @param list<string> $requested_scope Scope names requested by an agent; empty for browsers.
	 */
	public function open( string $binding_hash, ?string $ip_hash, int $ttl, ?string $redirect_to, string $purpose = 'login', ?int $link_user_id = null, string $kind = 'browser', array $requested_scope = array() ): Attempt {
		global $wpdb;

		if ( ! in_array( $kind, array( 'browser', 'agent' ), true ) || ! array_is_list( $requested_scope )
			|| count( array_filter( $requested_scope, 'is_string' ) ) !== count( $requested_scope ) ) {
			throw new \InvalidArgumentException( 'Invalid attempt kind or requested scope.' );
		}
		$scope = wp_json_encode( $requested_scope );
		if ( false === $scope ) {
			throw new \InvalidArgumentException( 'Could not encode the requested scope.' );
		}

		$now = time();
		$row = array(
			'public_id'       => bin2hex( random_bytes( 16 ) ),
			'correlation_id'  => bin2hex( random_bytes( 32 ) ),
			'binding_hash'    => $binding_hash,
			'nonce'           => rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- base64url of random bytes.
			// Shared with the verifier only; blinds the subject commitment on chain.
			'blinding_secret' => bin2hex( random_bytes( 32 ) ),
			'status'          => AttemptStatus::Pending->value,
			'purpose'         => $purpose,
			'link_user_id'    => $link_user_id,
			'kind'            => $kind,
			'requested_scope' => $scope,
			'ip_hash'         => $ip_hash,
			'redirect_to'     => $redirect_to,
			'created_at'      => gmdate( 'Y-m-d H:i:s', $now ),
			'expires_at'      => gmdate( 'Y-m-d H:i:s', $now + $ttl ),
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

	/**
	 * @return bool False when the reference was not stored (wpdb refuses a value longer than the column).
	 */
	public function set_verifier_ref( Attempt $attempt, string $ref ): bool {
		global $wpdb;
		return 1 === $wpdb->update( Schema::attempts_table(), array( 'verifier_ref' => $ref ), array( 'id' => $attempt->id ) );
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

	/**
	 * Attempts opened in the window, whatever became of them: failed and
	 * expired attempts cost a verifier call and a row too.
	 *
	 * @param string|null  $ip_hash One client's attempts, or every client's for the site-wide cap.
	 * @param Attempt|null $up_to   Count only attempts opened up to this one (by id). Checked
	 *                              after the insert, this is the attempt's rank in the window,
	 *                              which a parallel burst cannot push past the cap: ids are unique.
	 */
	public function count_recent( int $window, ?string $ip_hash = null, ?Attempt $up_to = null ): int {
		global $wpdb;
		$table = Schema::attempts_table();
		$sql   = "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$args  = array( gmdate( 'Y-m-d H:i:s', time() - $window ) );
		if ( null !== $ip_hash ) {
			$sql   .= ' AND ip_hash = %s';
			$args[] = $ip_hash;
		}
		if ( null !== $up_to ) {
			$sql   .= ' AND id <= %d';
			$args[] = $up_to->id;
		}

		return (int) $wpdb->get_var( $wpdb->prepare( $sql, ...$args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- placeholders only, built above; every value goes through prepare().
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
