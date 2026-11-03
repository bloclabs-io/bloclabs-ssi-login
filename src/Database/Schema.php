<?php
/**
 * The plugin's two tables.
 *
 * Login attempts are short-lived, written by anonymous visitors and updated by
 * webhooks, so they live in their own indexed table rather than in wp_options
 * transients (see docs/adr/0002-session-binding-custom-table.md).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Database;

final class Schema {

	public const VERSION        = '2';
	public const VERSION_OPTION = 'bloclabs_ssi_db_version';

	public static function attempts_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'bloclabs_ssi_attempts';
	}

	public static function identities_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'bloclabs_ssi_identities';
	}

	/**
	 * Runs on every load but costs one autoloaded option read when nothing changed.
	 */
	public static function maybe_upgrade(): void {
		if ( get_option( self::VERSION_OPTION ) !== self::VERSION ) {
			self::install();
		}
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset  = $wpdb->get_charset_collate();
		$attempts = self::attempts_table();
		$ids      = self::identities_table();

		// dbDelta is strict about formatting: one column per line, two spaces before the PRIMARY KEY definition.
		dbDelta(
			"CREATE TABLE {$attempts} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  public_id char(32) NOT NULL,
  correlation_id char(64) NOT NULL,
  binding_hash char(64) NOT NULL,
  nonce varchar(64) NOT NULL,
  blinding_secret char(64) NOT NULL DEFAULT '',
  status varchar(16) NOT NULL DEFAULT 'pending',
  verifier_ref varchar(191) DEFAULT NULL,
  ip_hash char(64) DEFAULT NULL,
  redirect_to text,
  firefly_event_id varchar(64) DEFAULT NULL,
  tx_ref varchar(191) DEFAULT NULL,
  subject_commitment char(64) DEFAULT NULL,
  presentation_hash char(64) DEFAULT NULL,
  user_id bigint(20) unsigned DEFAULT NULL,
  created_at datetime NOT NULL,
  expires_at datetime NOT NULL,
  checked_at datetime DEFAULT NULL,
  attested_at datetime DEFAULT NULL,
  consumed_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY public_id (public_id),
  UNIQUE KEY correlation_id (correlation_id),
  KEY status_expires (status,expires_at),
  KEY ip_created (ip_hash,created_at)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$ids} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  subject_hash char(64) NOT NULL,
  user_id bigint(20) unsigned NOT NULL,
  subject_label varchar(191) DEFAULT NULL,
  issuer varchar(191) DEFAULT NULL,
  created_at datetime NOT NULL,
  last_login_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY subject_hash (subject_hash),
  KEY user_id (user_id)
) {$charset};"
		);

		// Record the version only when both tables exist, so a failed CREATE is retried on the next load.
		if ( self::table_exists( $attempts ) && self::table_exists( $ids ) ) {
			update_option( self::VERSION_OPTION, self::VERSION, true );
		}
	}

	private static function table_exists( string $table ): bool {
		global $wpdb;
		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Called from uninstall.php only.
	 */
	public static function drop(): void {
		global $wpdb;
		// Table names come from $wpdb->prefix and constants, never from input.
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::attempts_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::identities_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		delete_option( self::VERSION_OPTION );
	}
}
