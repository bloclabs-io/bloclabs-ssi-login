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
}
