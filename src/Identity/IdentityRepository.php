<?php
/**
 * Links credential subjects to WordPress users.
 *
 * Subjects are stored as HMAC-SHA256(subject_key, subject_id): a database dump
 * does not list which DIDs hold accounts here. A short label is kept for the
 * user's profile screen ("did:key:z6Mk…a4Qx").
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

	public static function label( string $subject_id ): string {
		return strlen( $subject_id ) > 28 ? substr( $subject_id, 0, 18 ) . '…' . substr( $subject_id, -6 ) : $subject_id;
	}
}
