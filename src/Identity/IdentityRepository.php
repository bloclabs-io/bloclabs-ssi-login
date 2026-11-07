<?php
/**
 * Links credential subjects to WordPress users.
 *
 * Subjects are stored as HMAC-SHA256(subject_key, subject_id), so the table
 * does not list which DIDs hold accounts here. With BLOCLABS_SSI_SUBJECT_KEY in
 * wp-config.php, a full database dump cannot test guessed DIDs either; with the
 * stored fallback key, it can. A short label is kept for the
 * user's profile screen ("did:key #3f9a1c2e"): a keyed fingerprint that does not reveal the subject.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- custom table; lookups are by unique key.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

use BlocLabs\SsiLogin\Database\Schema;

final class IdentityRepository {

	public function user_id_for( string $subject_hash ): ?int {
		global $wpdb;
		$table = Schema::identities_table();
		$id    = $wpdb->get_var(
			$wpdb->prepare( "SELECT user_id FROM {$table} WHERE subject_hash = %s", $subject_hash ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
		return null === $id ? null : (int) $id;
	}

	/**
	 * @return bool False when the subject is already linked (to anyone).
	 */
	public function link( string $subject_hash, int $user_id, string $label, ?string $issuer ): bool {
		global $wpdb;
		$inserted = $wpdb->insert(
			Schema::identities_table(),
			array(
				'subject_hash'  => $subject_hash,
				'user_id'       => $user_id,
				'subject_label' => $label,
				'issuer'        => $issuer,
				'created_at'    => gmdate( 'Y-m-d H:i:s' ),
			)
		);
		return false !== $inserted;
	}

	/** @return list<array<string, mixed>> */
	public function for_user( int $user_id ): array {
		global $wpdb;
		$table = Schema::identities_table();
		return $wpdb->get_results( $wpdb->prepare( "SELECT id, subject_label FROM {$table} WHERE user_id = %d ORDER BY id", $user_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	public function unlink_owned( int $identity_id, int $user_id ): bool {
		global $wpdb;
		return 1 === $wpdb->delete(
			Schema::identities_table(),
			array(
				'id'      => $identity_id,
				'user_id' => $user_id,
			)
		);
	}

	public function touch( string $subject_hash ): void {
		global $wpdb;
		$wpdb->update(
			Schema::identities_table(),
			array( 'last_login_at' => gmdate( 'Y-m-d H:i:s' ) ),
			array( 'subject_hash' => $subject_hash )
		);
	}

	public function unlink_user( int $user_id ): void {
		global $wpdb;
		$wpdb->delete( Schema::identities_table(), array( 'user_id' => $user_id ) );
	}

	/**
	 * Credential links for an administrator or WP-CLI.
	 *
	 * The subject hash is not selected. Callers can show the label, the issuer
	 * and the dates without a way to print the hash or recover the subject id.
	 * Pass a user id to limit the rows to that account; omit it for the whole site.
	 *
	 * @return list<array{user_id: int, subject_label: string, issuer: string, created_at: string, last_login_at: string}>
	 */
	public function links_for( ?int $user_id = null ): array {
		global $wpdb;
		$table = Schema::identities_table();
		if ( null === $user_id ) {
			$rows = $wpdb->get_results(
				"SELECT user_id, subject_label, issuer, created_at, last_login_at FROM {$table} ORDER BY user_id ASC, id ASC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				ARRAY_A
			);
		} else {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT user_id, subject_label, issuer, created_at, last_login_at FROM {$table} WHERE user_id = %d ORDER BY id ASC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$user_id
				),
				ARRAY_A
			);
		}
		if ( ! is_array( $rows ) ) {
			return array();
		}

		$links = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$links[] = array(
				'user_id'       => (int) $row['user_id'],
				'subject_label' => (string) ( $row['subject_label'] ?? '' ),
				'issuer'        => (string) ( $row['issuer'] ?? '' ),
				'created_at'    => (string) ( $row['created_at'] ?? '' ),
				'last_login_at' => (string) ( $row['last_login_at'] ?? '' ),
			);
		}
		return $links;
	}

	/**
	 * An opaque label for the profile screen: the DID method (or "credential") and
	 * a short keyed fingerprint. It never contains the identifier, and without the
	 * subject key it cannot confirm a guessed one.
	 */
	public static function label( string $subject_id, string $key ): string {
		$kind = 1 === preg_match( '/^(did:[a-z0-9]+):/', $subject_id, $m ) ? $m[1] : 'credential';
		return $kind . ' #' . substr( hash_hmac( 'sha256', 'label|' . $subject_id, $key ), 0, 8 );
	}
}
