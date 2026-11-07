<?php
/**
 * Real SQL storage, lifecycle and per-site isolation for agent tokens (#88).
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- exercise the custom tables.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Cron\PurgeExpired;
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\TokenRepository;

final class TokenRepositoryTest extends IntegrationTestCase {

	/** @return array<string, mixed> */
	private function row( array $overrides = array() ): array {
		return array_merge(
			array(
				'token_hash'         => hash( 'sha256', 'test-token-' . wp_generate_uuid4() ),
				'user_id'            => self::factory()->user->create(),
				'delegated'          => 0,
				'agent_subject_hash' => hash_hmac( 'sha256', 'did:key:example', 'test-subject-key' ),
				'agent_label'        => 'Example agent',
				'issuer'             => 'https://issuer.example',
				'scope'              => '["read","content"]',
				'correlation_id'     => bin2hex( random_bytes( 32 ) ),
				'tx_ref'             => 'test-transaction',
				'firefly_event_id'   => 'test-event',
				'created_at'         => gmdate( 'Y-m-d H:i:s' ),
				'expires_at'         => gmdate( 'Y-m-d H:i:s', time() + HOUR_IN_SECONDS ),
			),
			$overrides
		);
	}

	public function test_round_trip_keeps_the_audit_trail_but_never_a_secret(): void {
		$repo          = new TokenRepository();
		$row           = $this->row();
		$row['token']  = 'bssi_' . str_repeat( 'a', 43 );
		$row['secret'] = 'must-not-be-stored';
		$this->assertTrue( $repo->store( $row ) );
		$stored = $repo->find( $row['token_hash'] );
		foreach ( array( 'token_hash', 'agent_subject_hash', 'agent_label', 'issuer', 'scope', 'correlation_id', 'tx_ref', 'firefly_event_id', 'created_at', 'expires_at' ) as $key ) {
			$this->assertSame( $row[ $key ], $stored[ $key ] );
		}
		$this->assertSame( $row['user_id'], (int) $stored['user_id'] );
		$this->assertSame( 0, (int) $stored['delegated'] );
		$this->assertNull( $stored['last_used_at'] );
		$this->assertNull( $stored['revoked_at'] );
		$this->assertArrayNotHasKey( 'token', $stored );
		$this->assertArrayNotHasKey( 'secret', $stored );
		$this->assertNull( $repo->find( "' OR 1=1 --" ) );
		$this->assertCount( 1, $repo->for_user( $row['user_id'] ) );
		$this->assertArrayNotHasKey( 'token_hash', $repo->for_user( $row['user_id'] )[0] );
		$this->assertArrayNotHasKey( 'agent_subject_hash', $repo->for_user( $row['user_id'] )[0] );
		$this->assertSame( array(), $repo->for_user( $row['user_id'] + 1 ) );
	}

	public function test_duplicate_hash_or_attestation_cannot_replace_a_token(): void {
		global $wpdb;
		$repo = new TokenRepository();
		$row  = $this->row();
		$this->assertTrue( $repo->store( $row ) );
		$errors = $wpdb->suppress_errors();
		try {
			$this->assertFalse( $repo->store( array_replace( $row, array( 'correlation_id' => str_repeat( 'd', 64 ) ) ) ) );
			$this->assertFalse( $repo->store( array_replace( $row, array( 'token_hash' => str_repeat( 'e', 64 ) ) ) ) );
		} finally {
			$wpdb->suppress_errors( $errors );
		}
		$this->assertSame( $row['correlation_id'], $repo->find( $row['token_hash'] )['correlation_id'] );
		$this->assertCount( 1, $repo->for_user( $row['user_id'] ) );
	}

	public function test_raw_tokens_and_malformed_scope_are_refused(): void {
		$repo = new TokenRepository();
		$row  = $this->row();
		foreach ( array( 'token_hash', 'agent_subject_hash', 'correlation_id' ) as $key ) {
			$this->assertFalse( $repo->store( array_replace( $row, array( $key => 'bssi_' . str_repeat( 'a', 43 ) ) ) ) );
		}
		foreach ( array( null, array( 'read' ), '[]', 'null', '"read"', '{"scope":"read"}', '[1]', 'invalid' ) as $scope ) {
			$this->assertFalse( $repo->store( array_replace( $row, array( 'scope' => $scope ) ) ) );
		}
		$this->assertSame( array(), $repo->for_user( $row['user_id'] ) );
	}

	public function test_failed_insert_reports_failure_and_cannot_create_an_authenticatable_row(): void {
		global $wpdb;
		$repo   = new TokenRepository();
		$row    = $this->row();
		$errors = $wpdb->suppress_errors();
		$deny   = static fn ( string $sql ): string => str_starts_with( $sql, 'INSERT INTO `' . Schema::tokens_table() . '`' ) ? 'INSERT INTO ssi_missing_test_table (id) VALUES (1)' : $sql;
		add_filter( 'query', $deny );
		try {
			$this->assertFalse( $repo->store( $row ) );
			$this->assertNull( $repo->find( $row['token_hash'] ) );
		} finally {
			remove_filter( 'query', $deny );
			$wpdb->suppress_errors( $errors );
		}
	}

	public function test_touch_is_atomic_throttled_and_stops_after_revocation_or_expiry(): void {
		$repo = new TokenRepository();
		$row  = $this->row();
		$now  = time();
		$hash = $row['token_hash'];
		$this->assertTrue( $repo->store( $row ) );
		$this->assertTrue( $repo->touch( $hash, $now ) );
		$this->assertFalse( $repo->touch( $hash, $now ) );
		$this->assertFalse( $repo->touch( $hash, $now + 59 ) );
		$this->assertTrue( $repo->touch( $hash, $now + 60 ) );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', $now + 60 ), $repo->find( $hash )['last_used_at'] );
		$this->assertFalse( $repo->touch( $hash, (int) strtotime( $row['expires_at'] . ' UTC' ) ) );
		$this->assertTrue( $repo->revoke( $hash ) );
		$revoked = $repo->find( $hash )['revoked_at'];
		$this->assertNotNull( $revoked );
		$this->assertFalse( $repo->revoke( $hash ) );
		$this->assertSame( $revoked, $repo->find( $hash )['revoked_at'] );
		$this->assertFalse( $repo->touch( $hash, $now + 120 ) );
		$this->assertFalse( $repo->revoke( str_repeat( 'f', 64 ) ) );
	}

	public function test_hourly_purge_keeps_recent_audit_rows_and_deletes_old_expiry_or_revocation(): void {
		global $wpdb;
		$repo   = new TokenRepository();
		$cutoff = time() - 30 * DAY_IN_SECONDS;
		$rows   = array();
		foreach ( array( 'live', 'expired_recently', 'expired_at_cutoff', 'revoked_recently', 'revoked_before_cutoff' ) as $key ) {
			$overrides = array( 'created_at' => gmdate( 'Y-m-d H:i:s', $cutoff - DAY_IN_SECONDS ) );
			if ( str_starts_with( $key, 'expired' ) ) {
				$overrides['expires_at'] = gmdate( 'Y-m-d H:i:s', 'expired_at_cutoff' === $key ? $cutoff : time() - 10 );
			}
			$rows[ $key ] = $this->row( $overrides );
			$this->assertTrue( $repo->store( $rows[ $key ] ) );
			if ( str_starts_with( $key, 'revoked' ) ) {
				$wpdb->update( Schema::tokens_table(), array( 'revoked_at' => gmdate( 'Y-m-d H:i:s', 'revoked_before_cutoff' === $key ? $cutoff - 1 : time() - 10 ) ), array( 'token_hash' => $rows[ $key ]['token_hash'] ) );
			}
		}
		$purge = new PurgeExpired( new AttemptRepository(), $repo );
		$this->assertSame( 2, $purge->run() );
		foreach ( $rows as $key => $row ) {
			$this->assertSame( in_array( $key, array( 'expired_at_cutoff', 'revoked_before_cutoff' ), true ), null === $repo->find( $row['token_hash'] ), $key );
		}
		$short_retention = static fn () => -1;
		add_filter( 'bloclabs_ssi_token_retention', $short_retention );
		try {
			$this->assertSame( 2, $purge->run() );
			$this->assertNotNull( $repo->find( $rows['live']['token_hash'] ) );
		} finally {
			remove_filter( 'bloclabs_ssi_token_retention', $short_retention );
		}
	}

	public function test_attempt_kind_scope_and_profile_link_defaults_round_trip(): void {
		$repo    = new AttemptRepository();
		$browser = $repo->open( str_repeat( 'a', 64 ), null, 180, null );
		$link    = $repo->open( str_repeat( 'b', 64 ), null, 180, null, 'link', 42 );
		$agent   = $repo->open( str_repeat( 'c', 64 ), null, 180, null, 'login', null, 'agent', array( 'read', 'content' ) );
		$this->assertSame( 'browser', $repo->find_by_public_id( $browser->public_id )->kind );
		$this->assertSame( array(), $browser->requested_scope );
		$this->assertSame( 'browser', $link->kind );
		$this->assertSame( 'link', $link->purpose );
		$this->assertSame( 42, $link->link_user_id );
		$loaded = $repo->find_by_public_id( $agent->public_id );
		$this->assertSame( 'agent', $loaded->kind );
		$this->assertSame( array( 'read', 'content' ), $loaded->requested_scope );
		$this->assertSame( 3, $repo->count_recent( 600 ), 'both kinds share the existing rate-limit counters' );
	}

	/** @group ms-required */
	public function test_tokens_are_isolated_per_site_including_purge_and_revocation(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Requires multisite.' );
		}
		$repo = new TokenRepository();
		$row  = $this->row();
		$this->assertTrue( $repo->store( $row ) );
		$this->use_real_tables();
		$blog = self::factory()->blog->create();
		switch_to_blog( $blog );
		try {
			Schema::install();
			$this->assertNull( $repo->find( $row['token_hash'] ) );
			$this->assertSame( array(), $repo->for_user( $row['user_id'] ) );
			$this->assertTrue( $repo->store( $row ) );
			$this->assertTrue( $repo->revoke( $row['token_hash'] ) );
			$this->assertSame( 1, $repo->purge( 0 ) );
			Schema::drop();
		} finally {
			restore_current_blog();
			wpmu_delete_blog( $blog, true );
			// DDL committed the site creation. Commit deletion too, so teardown's
			// rollback cannot resurrect a site whose tables have been dropped.
			self::commit_transaction();
		}
		$this->assertNotNull( $repo->find( $row['token_hash'] ) );
		$this->assertNull( $repo->find( $row['token_hash'] )['revoked_at'] );
	}
}
