<?php
/**
 * The plugin's attempts, identities and agent tokens tables.
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

	// Version 5 already added profile-link attempts (#81).
	public const VERSION        = '6';
	public const VERSION_OPTION = 'bloclabs_ssi_db_version';

	public static function attempts_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'bloclabs_ssi_attempts';
	}

	public static function identities_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'bloclabs_ssi_identities';
	}

	public static function tokens_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'bloclabs_ssi_tokens';
	}

	/**
	 * Runs on every load but costs one autoloaded option read when nothing changed.
	 */
	public static function maybe_upgrade(): bool {
		if ( get_option( self::VERSION_OPTION ) === self::VERSION ) {
			return true;
		}
		add_action( 'admin_notices', array( self::class, 'notice' ) );
		if ( (int) get_option( 'bloclabs_ssi_schema_retry_after', 0 ) > time() ) {
			return false;
		}
		update_option( 'bloclabs_ssi_schema_retry_after', time() + 300, false );
		try {
			self::install();
			return true;
		} catch ( \RuntimeException $e ) {
			return false;
		}
	}

	public static function notice(): void {
		if ( get_option( self::VERSION_OPTION ) !== self::VERSION && current_user_can( is_multisite() ? 'manage_network_options' : 'manage_options' ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'SSI Login could not install its database tables. Check database CREATE/ALTER permissions. Credential login is unavailable; installation retries after five minutes.', 'bloclabs-ssi-login' ) . '</p></div>';
		}
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset  = $wpdb->get_charset_collate();
		$attempts = self::attempts_table();
		$ids      = self::identities_table();
		$tokens   = self::tokens_table();

		// dbDelta is strict about formatting: one column per line, two spaces before the PRIMARY KEY definition.
		dbDelta(
			"CREATE TABLE {$attempts} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  public_id char(32) NOT NULL,
  correlation_id char(64) NOT NULL,
  binding_hash char(64) NOT NULL,
  nonce varchar(64) NOT NULL,
  blinding_secret char(64) NOT NULL DEFAULT '',
  purpose varchar(16) NOT NULL DEFAULT 'login',
  link_user_id bigint(20) unsigned DEFAULT NULL,
  kind varchar(16) NOT NULL DEFAULT 'browser',
  requested_scope text,
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
  KEY ip_created (ip_hash,created_at),
  KEY created (created_at)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$ids} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  subject_hash char(64) NOT NULL,
  user_id bigint(20) unsigned NOT NULL,
  subject_label varchar(191) DEFAULT NULL,
  issuer text,
  created_at datetime NOT NULL,
  last_login_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY subject_hash (subject_hash),
  KEY user_id (user_id)
) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$tokens} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  token_hash char(64) NOT NULL,
  user_id bigint(20) unsigned NOT NULL,
  delegated tinyint(1) unsigned NOT NULL DEFAULT 0,
  agent_subject_hash char(64) NOT NULL,
  agent_label varchar(191) NOT NULL,
  issuer text,
  scope text NOT NULL,
  correlation_id char(64) NOT NULL,
  tx_ref varchar(191) DEFAULT NULL,
  firefly_event_id varchar(64) DEFAULT NULL,
  created_at datetime NOT NULL,
  expires_at datetime NOT NULL,
  last_used_at datetime DEFAULT NULL,
  revoked_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY token_hash (token_hash),
  UNIQUE KEY correlation_id (correlation_id),
  KEY user_id (user_id),
  KEY expires_at (expires_at),
  KEY revoked_at (revoked_at)
) {$charset};"
		);

		// A failed CREATE or ALTER must leave the version unchanged so it can retry.
		if ( self::table_exists( $attempts ) && self::table_exists( $ids ) && self::table_exists( $tokens )
			&& self::column_exists( $attempts, 'kind' ) && self::column_exists( $attempts, 'requested_scope' ) ) {
			update_option( self::VERSION_OPTION, self::VERSION, true );
			delete_option( 'bloclabs_ssi_schema_retry_after' );
		} else {
			update_option( 'bloclabs_ssi_schema_retry_after', time() + 300, false );
			throw new \RuntimeException( 'SSI Login could not create its database tables. Check database permissions.' );
		}
	}

	private static function table_exists( string $table ): bool {
		global $wpdb;
		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	private static function column_exists( string $table, string $column ): bool {
		global $wpdb;
		return $column === $wpdb->get_var( $wpdb->prepare( 'SHOW COLUMNS FROM %i LIKE %s', $table, $wpdb->esc_like( $column ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Called from uninstall.php only.
	 */
	public static function drop(): void {
		global $wpdb;
		// Table names come from $wpdb->prefix and constants, never from input.
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::attempts_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::identities_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::tokens_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		delete_option( self::VERSION_OPTION );
	}
}
