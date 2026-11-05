<?php
/**
 * GET /status/{attempt} inside WordPress.
 *
 * Unknown and foreign attempts are covered with the binding cookie on /initiate.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent;
use BlocLabs\SsiLogin\Tests\Integration\Support\FireFlyHttpFake;

final class StatusRouteTest extends IntegrationTestCase {

	public function test_expires_pending_and_verified_attempts(): void {
		$pending = $this->open_attempt();
		$this->backdate(
			(string) $pending['data']['attempt'],
			array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 120 ) )
		);
		FireFlyHttpFake::instance()->calls = 0;

		$pending_status = $this->dispatch( 'GET', '/status/' . $pending['data']['attempt'] );
		$this->assert_http( 200, $pending_status );
		$this->assertSame( 'expired', $pending_status->get_data()['status'] );
		$this->assertSame( 'expired', $this->attempt_row( (string) $pending['data']['attempt'] )['status'] );
		$this->assertSame( 0, FireFlyHttpFake::instance()->calls, 'expiry does not ask FireFly' );

		$verified = $this->open_attempt();
		$this->attest( $verified['row'] );
		$this->assertSame( 'verified', $this->attempt_row( (string) $verified['data']['attempt'] )['status'] );
		$this->backdate(
			(string) $verified['data']['attempt'],
			array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 120 ) )
		);
		FireFlyHttpFake::instance()->calls = 0;

		$verified_status = $this->dispatch( 'GET', '/status/' . $verified['data']['attempt'] );
		$this->assert_http( 200, $verified_status );
		$this->assertSame( 'expired', $verified_status->get_data()['status'] );
		$this->assertSame( 'expired', $this->attempt_row( (string) $verified['data']['attempt'] )['status'] );
		$this->assertSame( 0, FireFlyHttpFake::instance()->calls );
	}

	public function test_polling_fallback_applies_an_attestation(): void {
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$delivery  = CapturedLoginEvent::delivery_for( (string) $opened['row']['correlation_id'], (string) $opened['row']['blinding_secret'] );
		FireFlyHttpFake::instance()->serve( $delivery );

		// Webhook mode, and the attempt is younger than poll_fallback_after: do not poll.
		$early = $this->dispatch( 'GET', '/status/' . $public_id );
		$this->assert_http( 200, $early );
		$this->assertSame( 'pending', $early->get_data()['status'] );
		$this->assertSame( 0, FireFlyHttpFake::instance()->calls );

		$this->backdate( $public_id, array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 30 ) ) );

		$settled = $this->dispatch( 'GET', '/status/' . $public_id );
		$this->assert_http( 200, $settled );
		$this->assertSame( 'verified', $settled->get_data()['status'] );
		$this->assertGreaterThan( 0, FireFlyHttpFake::instance()->calls );
		$this->assertStringContainsString( '/blockchainevents', FireFlyHttpFake::instance()->urls[0] );

		$row     = $this->attempt_row( $public_id );
		$subject = (string) CapturedLoginEvent::fixture()['subject'];
		$this->assertSame( 'verified', $row['status'] );
		$this->assertSame(
			Attestation::subject_commitment( (string) $opened['row']['correlation_id'], (string) $opened['row']['blinding_secret'], $subject ),
			$row['subject_commitment']
		);
		$this->assertSame( (string) CapturedLoginEvent::fixture()['presentation_hash'], $row['presentation_hash'] );
	}
	public function test_polling_has_one_shared_scan_and_a_failure_cooldown(): void {
		$this->configure( array( 'event_mode' => 'poll' ) );
		$first = $this->open_attempt();
		$this->dispatch( 'GET', '/status/' . $first['data']['attempt'] );
		$this->assertSame( 1, FireFlyHttpFake::instance()->calls );
		$second = $this->open_attempt();
		$this->dispatch( 'GET', '/status/' . $second['data']['attempt'] );
		$this->assertSame( 1, FireFlyHttpFake::instance()->calls, 'another browser shares the cooldown' );

		delete_option( 'bloclabs_ssi_poll_after' );
		FireFlyHttpFake::instance()->status = 503;
		$third                              = $this->open_attempt();
		$this->dispatch( 'GET', '/status/' . $third['data']['attempt'] );
		$this->assertSame( 2, FireFlyHttpFake::instance()->calls );
		$this->assertGreaterThanOrEqual( time() + 28, (int) get_option( 'bloclabs_ssi_poll_after' ) );
	}

	public function test_another_connection_holds_the_scan_lock(): void {
		$this->configure( array( 'event_mode' => 'poll' ) );
		$opened = $this->open_attempt();
		$lock   = 'ssi_poll_' . md5( \BlocLabs\SsiLogin\Database\Schema::attempts_table() );
		$peer   = new \mysqli( DB_HOST, DB_USER, DB_PASSWORD, DB_NAME ); // phpcs:ignore WordPress.DB.RestrictedClasses.mysql__mysqli -- a second connection must contend with the real wpdb connection.
		try {
			$peer->query( "SELECT GET_LOCK('" . $peer->real_escape_string( $lock ) . "', 0)" );
			$this->dispatch( 'GET', '/status/' . $opened['data']['attempt'] );
			$this->assertSame( 0, FireFlyHttpFake::instance()->calls );
		} finally {
			$peer->close();
		}
		$this->backdate( $opened['data']['attempt'], array( 'checked_at' => null ) );
		$this->dispatch( 'GET', '/status/' . $opened['data']['attempt'] );
		$this->assertSame( 1, FireFlyHttpFake::instance()->calls, 'the lock is released with the connection' );
	}

	public function test_pages_with_tied_timestamps_use_protocol_order_and_clock_margin(): void {
		$this->configure( array( 'event_mode' => 'poll' ) );
		$opened                           = $this->open_attempt();
		$target                           = CapturedLoginEvent::delivery_for( $opened['row']['correlation_id'], $opened['row']['blinding_secret'] )['blockchainEvent'];
		$other                            = $target;
		$other['output']['correlationId'] = '0x' . str_repeat( 'ab', 32 );
		FireFlyHttpFake::instance()->blockchain_events = array_merge( array_fill( 0, 50, $other ), array( $target ) );
		$response                                      = $this->dispatch( 'GET', '/status/' . $opened['data']['attempt'] );
		$this->assertSame( 'verified', $response->get_data()['status'] );
		$this->assertCount( 2, FireFlyHttpFake::instance()->urls );
		parse_str( (string) wp_parse_url( FireFlyHttpFake::instance()->urls[1], PHP_URL_QUERY ), $query );
		$this->assertSame( '-protocolid', $query['sort'] );
		$this->assertSame( '50', $query['skip'] );
		$this->assertLessThanOrEqual( time() - 3590, strtotime( substr( $query['timestamp'], 2 ) ) );
	}
}
