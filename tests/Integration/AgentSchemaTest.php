<?php
/**
 * Upgrade existing browser/profile attempts without losing data (#88).
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- real migration checks.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Session\AttemptRepository;

final class AgentSchemaTest extends IntegrationTestCase {

	/** Restores the version-5 layout introduced by profile linking. */
	private function downgrade(): void {
		global $wpdb;
		$this->use_real_tables();
		$wpdb->query( $wpdb->prepare( 'ALTER TABLE %i DROP COLUMN kind, DROP COLUMN requested_scope', Schema::attempts_table() ) );
		$wpdb->query( $wpdb->prepare( 'DROP TABLE %i', Schema::tokens_table() ) );
		update_option( Schema::VERSION_OPTION, '5' );
		delete_option( 'bloclabs_ssi_schema_retry_after' );
	}

	public function test_upgrade_from_profile_link_schema_preserves_attempts_and_identities(): void {
		global $wpdb;
		$repo    = new AttemptRepository();
		$browser = $repo->open( str_repeat( 'a', 64 ), null, 180, '/account' );
		$link    = $repo->open( str_repeat( 'b', 64 ), null, 180, null, 'link', 42 );
		$ids     = new IdentityRepository();
		$this->assertTrue( $ids->link( str_repeat( 'c', 64 ), 42, 'Example', 'https://issuer.example' ) );
		$this->downgrade();
		try {
			$this->assertTrue( Schema::maybe_upgrade() );
			$this->assertSame( Schema::VERSION, get_option( Schema::VERSION_OPTION ) );
			$loaded = $repo->find_by_public_id( $browser->public_id );
			$this->assertSame( 'browser', $loaded->kind );
			$this->assertSame( array(), $loaded->requested_scope );
			$this->assertSame( $browser->binding_hash, $loaded->binding_hash );
			$this->assertSame( $browser->correlation_id, $loaded->correlation_id );
			$this->assertSame( '/account', $loaded->redirect_to );
			$loaded = $repo->find_by_public_id( $link->public_id );
			$this->assertSame( 'browser', $loaded->kind );
			$this->assertSame( 'link', $loaded->purpose );
			$this->assertSame( 42, $loaded->link_user_id );
			$this->assertSame( 42, $ids->user_id_for( str_repeat( 'c', 64 ) ) );
			$this->assertSame( Schema::tokens_table(), $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( Schema::tokens_table() ) ) ) );
			Schema::install();
			$this->assertSame( $browser->id, $repo->find_by_public_id( $browser->public_id )->id, 'repeat installation is safe' );
		} finally {
			Schema::install();
		}
	}

	public function test_failed_alter_keeps_the_old_version_and_retries_after_cooldown(): void {
		$this->downgrade();
		$alter_count = 0;
		$deny        = static function ( string $sql ) use ( &$alter_count ): string {
			if ( str_starts_with( $sql, 'ALTER TABLE ' . Schema::attempts_table() ) ) {
				++$alter_count;
				return 'SELECT 1';
			}
			return $sql;
		};
		add_filter( 'query', $deny );
		try {
			$this->assertFalse( Schema::maybe_upgrade() );
			$this->assertGreaterThan( 0, $alter_count );
			$this->assertSame( '5', get_option( Schema::VERSION_OPTION ) );
			$previous = $alter_count;
			$this->assertFalse( Schema::maybe_upgrade() );
			$this->assertSame( $previous, $alter_count );
		} finally {
			remove_filter( 'query', $deny );
			delete_option( 'bloclabs_ssi_schema_retry_after' );
			Schema::install();
		}
		$this->assertTrue( Schema::maybe_upgrade() );
	}

	public function test_failed_tokens_create_cannot_mark_the_migration_complete(): void {
		$this->downgrade();
		$deny = static fn ( string $sql ): string => str_starts_with( $sql, 'CREATE TABLE ' . Schema::tokens_table() ) ? 'SELECT 1' : $sql;
		add_filter( 'query', $deny );
		try {
			$this->assertFalse( Schema::maybe_upgrade() );
			$this->assertSame( '5', get_option( Schema::VERSION_OPTION ) );
		} finally {
			remove_filter( 'query', $deny );
			Schema::install();
		}
		$this->assertSame( Schema::VERSION, get_option( Schema::VERSION_OPTION ) );
	}
}
