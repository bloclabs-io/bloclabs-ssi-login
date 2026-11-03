<?php
/**
 * POST /firefly/events inside WordPress.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Rest\WebhookController;
use BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent;
use BlocLabs\SsiLogin\Tests\Integration\Support\FireFlyHttpFake;

final class WebhookRouteTest extends IntegrationTestCase {

	public function test_wrong_secret_is_refused(): void {
		$opened   = $this->open_attempt();
		$delivery = CapturedLoginEvent::delivery_for( (string) $opened['row']['correlation_id'] );
		FireFlyHttpFake::instance()->serve( $delivery );

		$response = $this->dispatch(
			'POST',
			'/firefly/events',
			$delivery,
			array( WebhookController::SECRET_HEADER => 'wrong-secret-wrong-secret-wrong-xx' ),
			false
		);

		$this->assert_http( 401, $response );
		$this->assertSame( 'bloclabs_ssi_webhook_auth', $this->error_code( $response ) );
		$this->assertSame( 0, FireFlyHttpFake::instance()->calls );
		$this->assertSame( 'pending', $this->attempt_row( (string) $opened['data']['attempt'] )['status'] );
	}

	public function test_short_secret_is_refused(): void {
		$this->configure( array( 'webhook_secret' => 'short-secret' ) );
		$opened   = $this->open_attempt();
		$delivery = CapturedLoginEvent::delivery_for( (string) $opened['row']['correlation_id'] );
		FireFlyHttpFake::instance()->serve( $delivery );

		$response = $this->dispatch(
			'POST',
			'/firefly/events',
			$delivery,
			array( WebhookController::SECRET_HEADER => 'short-secret' ),
			false
		);

		$this->assert_http( 401, $response );
		$this->assertSame( 0, FireFlyHttpFake::instance()->calls );
		$this->assertSame( 'pending', $this->attempt_row( (string) $opened['data']['attempt'] )['status'] );
	}

	public function test_body_is_never_trusted(): void {
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$real      = CapturedLoginEvent::delivery_for( (string) $opened['row']['correlation_id'], (string) $opened['row']['blinding_secret'] );
		FireFlyHttpFake::instance()->serve( $real );

		$lie                                        = $real;
		$lie['blockchainEvent']['output']['result'] = '2';
		$lie['blockchainEvent']['output']['subjectCommitment'] = '0x' . str_repeat( '11', 32 );
		$lie['blockchainEvent']['info']['removed']             = true;

		$applied = $this->dispatch(
			'POST',
			'/firefly/events',
			$lie,
			array( WebhookController::SECRET_HEADER => self::WEBHOOK_SECRET ),
			false
		);
		$this->assert_http( 204, $applied );

		$row = $this->attempt_row( $public_id );
		$this->assertSame( 'verified', $row['status'] );
		$this->assertSame(
			Attestation::subject_commitment( (string) $opened['row']['correlation_id'], (string) $opened['row']['blinding_secret'], (string) CapturedLoginEvent::fixture()['subject'] ),
			$row['subject_commitment']
		);
		$this->assertNotSame( str_repeat( '11', 32 ), $row['subject_commitment'] );
		$this->assertStringContainsString( '/events/' . $real['id'], FireFlyHttpFake::instance()->urls[0] );

		// A body FireFly cannot confirm does nothing, however complete it looks.
		$second = $this->open_attempt();
		$missed = CapturedLoginEvent::delivery_for( (string) $second['row']['correlation_id'], (string) $second['row']['blinding_secret'] );
		FireFlyHttpFake::instance()->serve( $missed );
		FireFlyHttpFake::instance()->status = 404;

		$ignored = $this->dispatch(
			'POST',
			'/firefly/events',
			$missed,
			array( WebhookController::SECRET_HEADER => self::WEBHOOK_SECRET ),
			false
		);
		$this->assert_http( 204, $ignored );
		$this->assertSame( 'pending', $this->attempt_row( (string) $second['data']['attempt'] )['status'] );
	}

	public function test_duplicate_delivery_changes_nothing(): void {
		$opened = $this->open_attempt();
		$this->attest( $opened['row'] );
		$before = $this->attempt_row( (string) $opened['data']['attempt'] );

		$this->attest( $opened['row'] );
		$after = $this->attempt_row( (string) $opened['data']['attempt'] );

		$this->assertSame( $before, $after );
		$this->assertSame( 'verified', $after['status'] );
	}

	public function test_removed_log_is_ignored(): void {
		$opened = $this->open_attempt();
		$this->attest( $opened['row'], true );

		$row = $this->attempt_row( (string) $opened['data']['attempt'] );
		$this->assertSame( 'pending', $row['status'] );
		$this->assertNull( $row['subject_commitment'] );
		$this->assertNull( $row['firefly_event_id'] );
	}
}
