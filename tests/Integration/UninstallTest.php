<?php
/**
 * uninstall.php drops the tables and the options.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Cron\PurgeExpired;
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Lifecycle;

final class UninstallTest extends IntegrationTestCase {

	public function test_uninstall_drops_the_tables_and_options(): void {
		global $wpdb;

		$this->use_real_tables();
		Lifecycle::activate();
		$this->assertSame( Schema::VERSION, get_option( Schema::VERSION_OPTION ) );
		$this->assertIsArray( get_option( Settings::OPTION ) );
		$this->assertNotSame( '', (string) get_option( Settings::SUBJECT_KEY_OPTION ) );
		$this->assertNotFalse( wp_next_scheduled( PurgeExpired::HOOK ) );

		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'bloclabs-ssi-login/bloclabs-ssi-login.php' );
		}

		// Include, not require_once: the file has to run in this process even if a previous test loaded it.
		include dirname( \BlocLabs\SsiLogin\PLUGIN_FILE ) . '/uninstall.php';

		$attempts   = Schema::attempts_table();
		$identities = Schema::identities_table();
		$this->assertNull( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $attempts ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertNull( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $identities ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertFalse( get_option( Schema::VERSION_OPTION ) );
		$this->assertFalse( get_option( Settings::OPTION ) );
		$this->assertFalse( get_option( Settings::SUBJECT_KEY_OPTION ) );
		$this->assertFalse( wp_next_scheduled( PurgeExpired::HOOK ) );
	}
}
