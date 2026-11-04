<?php
/**
 * Installation failure and split-origin login regressions (#32).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Assets\AssetManager;
use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Lifecycle;

final class InstallationTest extends IntegrationTestCase {

	public function test_split_origin_uses_the_login_site_rest_entrypoint(): void {
		update_option( 'home', 'https://public.example' );
		update_option( 'siteurl', 'https://login.example/wp' );
		$assets = new AssetManager( new Settings() );
		$this->assertSame( site_url( 'index.php?rest_route=/bloclabs-ssi/v1/' ), $assets->rest_base() );
		update_option( 'home', 'http://login.example/wp' );
		update_option( 'siteurl', 'http://login.example/wp' );
		$this->assertSame( rest_url( 'bloclabs-ssi/v1/' ), $assets->rest_base() );
	}

	public function test_failed_create_stops_activation_and_retries_are_throttled(): void {
		global $wpdb;
		$this->use_real_tables();
		$prefix       = $wpdb->prefix;
		$wpdb->prefix = 'ssi_missing_';
		$creates      = 0;
		$deny         = static function ( string $sql ) use ( &$creates ): string {
			if ( str_starts_with( $sql, 'CREATE TABLE ssi_missing_' ) ) {
				++$creates;
				return 'SELECT 1'; // Simulate CREATE failing to produce a table without changing database grants.
			}
			return $sql;
		};
		add_filter( 'query', $deny );
		delete_option( Schema::VERSION_OPTION );
		delete_option( 'bloclabs_ssi_schema_retry_after' );
		try {
			try {
				Lifecycle::activate();
				$this->fail( 'Activation succeeded without tables' );
			} catch ( \WPDieException $e ) {
				$this->assertStringContainsString( 'could not create', $e->getMessage() );
			}
			$this->assertFalse( get_option( Schema::VERSION_OPTION ) );
			$this->assertSame( 2, $creates );
			$this->assertFalse( Schema::maybe_upgrade() );
			$this->assertSame( 2, $creates, 'a second request in the cooldown does not retry CREATE' );
		} finally {
			remove_filter( 'query', $deny );
			$wpdb->prefix = $prefix;
		}
		delete_option( 'bloclabs_ssi_schema_retry_after' );
		$this->assertTrue( Schema::maybe_upgrade() );
		$this->assertSame( Schema::VERSION, get_option( Schema::VERSION_OPTION ) );
	}
}
