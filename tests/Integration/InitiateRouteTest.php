<?php
/**
 * POST /initiate inside WordPress.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Support\ClientIp;
use BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class InitiateRouteTest extends IntegrationTestCase {

	protected function tearDown(): void {
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		parent::tearDown();
	}

	public function test_page_token_is_required(): void {
		$missing = $this->dispatch( 'POST', '/initiate', array(), array(), false );
		$this->assert_http( 403, $missing );
		$this->assertSame( 'bloclabs_ssi_nonce', $this->error_code( $missing ) );

		$wrong = $this->dispatch( 'POST', '/initiate', array(), array( 'X-Bloclabs-Ssi-Token' => 'not-a-page-token' ), false );
		$this->assert_http( 403, $wrong );
		$this->assertSame( 'bloclabs_ssi_nonce', $this->error_code( $wrong ) );
		$this->assertSame( 0, $this->attempt_count() );
	}

	public function test_refuses_without_the_verifier_authorization_header(): void {
		$this->configure( array( 'verifier_auth_header' => '' ) );

		$response = $this->dispatch( 'POST', '/initiate' );

		$this->assert_http( 503, $response );
		$this->assertSame( 'bloclabs_ssi_unavailable', $this->error_code( $response ) );
		$this->assertSame( 0, $this->attempt_count() );
		$this->assertSame( 0, VerifierFake::instance()->creates );
	}

	public function test_issues_a_binding_cookie(): void {
		$opened = $this->open_attempt();
		$secret = $this->binding_cookie();

		$this->assertNotSame( '', $secret );
		$this->assertSame( (string) $opened['row']['correlation_id'], VerifierFake::instance()->last_request?->correlation_id );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', (string) $opened['row']['blinding_secret'] );
		$this->assertSame( (string) $opened['row']['blinding_secret'], VerifierFake::instance()->last_request?->blinding_secret, 'the bridge gets the secret that blinds the commitment' );
		$this->assertArrayNotHasKey( 'blinding_secret', $opened['data'], 'the browser never sees it' );

		$headers = implode( "\n", headers_list() );
		if ( str_contains( $headers, 'bloclabs_ssi=' ) ) {
			$this->assertMatchesRegularExpression( '/bloclabs_ssi=[^;]+;[^\\n]*HttpOnly/i', $headers );
			$this->assertMatchesRegularExpression( '/bloclabs_ssi=[^;]+;[^\\n]*SameSite=Strict/i', $headers );
		}

		$public_id = (string) $opened['data']['attempt'];
		$owned     = $this->dispatch( 'GET', '/status/' . $public_id );
		$this->assert_http( 200, $owned );
		$this->assertSame( 'pending', $owned->get_data()['status'] );

		$this->forget_browser();
		$missing = $this->dispatch( 'GET', '/status/' . $public_id );
		$this->assert_http( 404, $missing );
		$this->assertSame( 'bloclabs_ssi_unknown', $this->error_code( $missing ) );

		$this->restore_browser( 'some-other-browser' );
		$foreign = $this->dispatch( 'GET', '/status/' . $public_id );
		$this->assert_http( 404, $foreign );
		$this->assertSame( 'bloclabs_ssi_unknown', $this->error_code( $foreign ) );

		$this->restore_browser( $secret );
		$unknown = $this->dispatch( 'GET', '/status/' . str_repeat( 'ab', 16 ) );
		$this->assert_http( 404, $unknown );
		$this->assertSame( 'bloclabs_ssi_unknown', $this->error_code( $unknown ) );

		// The refused reads did not move the attempt.
		$this->assertSame( 'pending', $this->attempt_row( $public_id )['status'] );
	}

	public function test_per_ip_limit_counts_every_attempt(): void {
		$this->configure( array( 'max_pending_per_ip' => 2 ) );
		$verifier = VerifierFake::instance();

		// A verifier failure still opens a row, and that row counts.
		$verifier->create_error = new VerifierException( 'down', 503 );
		$failed                 = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 503, $failed );
		$this->assertSame( 'failed', $this->only_attempt_status() );

		$verifier->create_error = null;
		$opened                 = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 201, $opened );
		$this->assertSame( 2, $this->attempt_count() );

		$limited = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 429, $limited );
		$this->assertSame( 'bloclabs_ssi_rate_limited', $this->error_code( $limited ) );
		$this->assertSame( 2, $this->attempt_count() );

		// Another client is its own bucket.
		$_SERVER['REMOTE_ADDR'] = '203.0.113.11';
		$other                  = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 201, $other );
		$this->assertSame( 3, $this->attempt_count() );
	}

	/**
	 * M2 (#26): proxies append their peer to X-Forwarded-For, so a sender who
	 * writes a fresh first entry each time must still land in one bucket.
	 */
	public function test_a_forged_forwarded_for_entry_does_not_escape_the_limit(): void {
		$this->configure(
			array(
				'max_pending_per_ip' => 2,
				'client_ip_header'   => 'HTTP_X_FORWARDED_FOR',
			)
		);

		foreach ( array( '10.0.0.1', '10.0.0.2' ) as $forged ) {
			$_SERVER['HTTP_X_FORWARDED_FOR'] = $forged . ', 203.0.113.50';
			$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );
		}

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.3, 203.0.113.50';
		$limited                         = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 429, $limited );
		$this->assertSame( 'bloclabs_ssi_rate_limited', $this->error_code( $limited ) );
		$this->assertSame( 2, $this->attempt_count() );

		// Naming a victim first does not charge the victim: the victim's own requests still go through.
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.51';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );
		$this->assertSame( 3, $this->attempt_count() );
	}

	public function test_a_forwarded_header_that_cannot_name_the_client_is_refused(): void {
		$this->configure(
			array(
				'client_ip_header'  => 'HTTP_X_FORWARDED_FOR',
				'client_ip_proxies' => 2,
			)
		);

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.50';
		$response                        = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 503, $response );
		$this->assertSame( 'bloclabs_ssi_unavailable', $this->error_code( $response ) );
		$this->assertSame( 0, $this->attempt_count() );
		$this->assertSame( 0, VerifierFake::instance()->creates );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.50, 192.0.2.10';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );
	}

	/**
	 * L19 (#26): one IPv6 /64 is one client.
	 */
	public function test_addresses_in_one_ipv6_prefix_share_the_limit(): void {
		$this->configure( array( 'max_pending_per_ip' => 2 ) );

		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::1';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:ffff::2';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );

		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::3';
		$limited                = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 429, $limited );
		$this->assertSame( 'bloclabs_ssi_rate_limited', $this->error_code( $limited ) );

		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:3::1';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );
		$this->assertSame( 3, $this->attempt_count() );
	}

	/**
	 * L19 (#26): the site-wide cap holds whatever the addresses.
	 */
	public function test_the_site_wide_cap_counts_every_client(): void {
		$this->configure(
			array(
				'max_pending_per_ip' => 10,
				'max_pending_total'  => 2,
			)
		);

		$_SERVER['REMOTE_ADDR'] = '203.0.113.21';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.22';
		$this->assert_http( 201, $this->dispatch( 'POST', '/initiate' ) );

		$_SERVER['REMOTE_ADDR'] = '203.0.113.23';
		$limited                = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 429, $limited );
		$this->assertSame( 'bloclabs_ssi_rate_limited', $this->error_code( $limited ) );
		$this->assertSame( 2, $this->attempt_count() );
		$this->assertSame( 2, VerifierFake::instance()->creates );
	}

	/**
	 * L18 (#26): after the insert, an attempt's rank in the window decides, so
	 * concurrent inserts that all passed the pre-check cannot all pass.
	 */
	public function test_recent_counts_rank_attempts_by_id(): void {
		$attempts               = Plugin::instance()->attempts();
		$settings               = Plugin::instance()->settings();
		$a                      = (string) ClientIp::hash( $settings );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.11';
		$b                      = (string) ClientIp::hash( $settings );
		$this->assertNotSame( $a, $b );

		$first  = $attempts->open( str_repeat( '1', 64 ), $a, 180, null );
		$second = $attempts->open( str_repeat( '2', 64 ), $a, 180, null );
		$third  = $attempts->open( str_repeat( '3', 64 ), $b, 180, null );
		$fourth = $attempts->open( str_repeat( '4', 64 ), $a, 180, null );

		$this->assertSame( 3, $attempts->count_recent( 600, $a ) );
		$this->assertSame( 1, $attempts->count_recent( 600, $b ) );
		$this->assertSame( 4, $attempts->count_recent( 600 ) );

		$this->assertSame( 1, $attempts->count_recent( 600, $a, $first ) );
		$this->assertSame( 2, $attempts->count_recent( 600, $a, $second ) );
		$this->assertSame( 2, $attempts->count_recent( 600, $a, $third ), 'another client\'s row does not count' );
		$this->assertSame( 3, $attempts->count_recent( 600, $a, $fourth ) );
		$this->assertSame( 3, $attempts->count_recent( 600, null, $third ) );

		$this->backdate( $first->public_id, array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 601 ) ) );
		$this->assertSame( 2, $attempts->count_recent( 600, $a ), 'outside the window' );
		$this->assertSame( 3, $attempts->count_recent( 600 ) );
	}

	/**
	 * L20 (#30): a row that cannot be stored used to escape as a 500 with the
	 * exception's path in it, after a cookie had been set for the missing attempt.
	 */
	public function test_a_storage_failure_answers_503_without_a_cookie(): void {
		global $wpdb;
		$table = \BlocLabs\SsiLogin\Database\Schema::attempts_table();
		add_filter(
			'query',
			static fn ( $query ) => str_contains( (string) $query, "INSERT INTO `{$table}`" ) ? "INSERT INTO `{$table}` (no_such_column) VALUES (1)" : $query
		);

		$suppressed = $wpdb->suppress_errors();
		try {
			$response = $this->dispatch( 'POST', '/initiate' );
		} finally {
			$wpdb->suppress_errors( $suppressed );
		}

		$this->assert_http( 503, $response );
		$this->assertSame( 'bloclabs_ssi_unavailable', $this->error_code( $response ) );
		$this->assertSame( 0, $this->attempt_count() );
		$this->assertSame( '', $this->binding_cookie(), 'no cookie for an attempt that does not exist' );
		$this->assertSame( 0, VerifierFake::instance()->creates );
	}

	/**
	 * L22 (#30): wpdb refuses a value longer than the column and the attempt
	 * then had no verifier reference, so every completion of it failed.
	 */
	public function test_a_verifier_reference_that_cannot_be_stored_fails_the_attempt_here(): void {
		VerifierFake::instance()->verifier_ref = str_repeat( 'r', 192 );

		$response = $this->dispatch( 'POST', '/initiate' );

		$this->assert_http( 503, $response );
		$this->assertSame( 'bloclabs_ssi_unavailable', $this->error_code( $response ) );
		$this->assertSame( 1, $this->attempt_count() );
		$this->assertSame( 'failed', $this->only_attempt_status() );
	}

	private function only_attempt_status(): string {
		global $wpdb;
		$table  = \BlocLabs\SsiLogin\Database\Schema::attempts_table();
		$status = $wpdb->get_var( "SELECT status FROM {$table} LIMIT 1" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return (string) $status;
	}
}
