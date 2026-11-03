<?php
/**
 * Activation creates the plugin's tables.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Lifecycle;

final class ActivationTest extends IntegrationTestCase {

	public function test_activation_creates_tables_and_records_the_schema_version(): void {
		global $wpdb;

		$this->use_real_tables();
		$attempts   = Schema::attempts_table();
		$identities = Schema::identities_table();
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $attempts ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $identities ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		delete_option( Schema::VERSION_OPTION );
		$this->assertNull( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $attempts ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		Lifecycle::activate();

		$this->assertSame( $attempts, $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $attempts ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertSame( $identities, $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $identities ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertSame( Schema::VERSION, get_option( Schema::VERSION_OPTION ) );
	}
}
