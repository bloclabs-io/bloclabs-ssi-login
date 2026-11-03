<?php
/**
 * POST /initiate inside WordPress.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class InitiateRouteTest extends IntegrationTestCase {

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

	private function only_attempt_status(): string {
		global $wpdb;
		$table  = \BlocLabs\SsiLogin\Database\Schema::attempts_table();
		$status = $wpdb->get_var( "SELECT status FROM {$table} LIMIT 1" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return (string) $status;
	}
}
