<?php
/**
 * Exercise real SQL compare-and-set and login side-effect ordering (#33).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent;
use BlocLabs\SsiLogin\Tests\Integration\Support\FireFlyHttpFake;

final class StateRegressionTest extends IntegrationTestCase {

	public function test_a_stale_writer_cannot_overwrite_the_winning_transition(): void {
		$opened = $this->open_attempt();
		$stale  = Attempt::from_row( $opened['row'] );
		$repo   = Plugin::instance()->attempts();
		$this->assertTrue( $repo->transition( $stale, AttemptStatus::Verified ) );
		$this->assertFalse( $repo->transition( $stale, AttemptStatus::Rejected ) );
		$this->assertSame( 'verified', $this->attempt_row( $stale->public_id )['status'] );
		$verified = $repo->find_by_public_id( $stale->public_id );
		$this->assertTrue( $repo->transition( $verified, AttemptStatus::Consumed ) );
		$this->assertFalse( $repo->transition( $verified, AttemptStatus::Failed ) );
		$this->assertSame( 'consumed', $this->attempt_row( $stale->public_id )['status'] );
	}

	public function test_poll_claim_is_throttled_even_when_no_event_is_found(): void {
		$this->configure( array( 'event_mode' => Settings::EVENT_MODE_POLL ) );
		$opened = $this->open_attempt();
		$id     = $opened['data']['attempt'];
		$this->assert_http( 200, $this->dispatch( 'GET', '/status/' . $id ) );
		$calls = FireFlyHttpFake::instance()->calls;
		$this->assertGreaterThan( 0, $calls );
		$this->assert_http( 200, $this->dispatch( 'GET', '/status/' . $id ) );
		$this->assertSame( $calls, FireFlyHttpFake::instance()->calls );
		$this->assertSame( 'pending', $this->attempt_row( $id )['status'] );
	}

	public function test_rejection_and_expired_verification_cannot_verify_an_attempt(): void {
		$opened                                       = $this->open_attempt();
		$event                                        = CapturedLoginEvent::delivery_for( $opened['row']['correlation_id'], $opened['row']['blinding_secret'] );
		$event['blockchainEvent']['output']['result'] = '2';
		FireFlyHttpFake::instance()->serve( $event );
		$this->backdate( $opened['data']['attempt'], array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 30 ) ) );
		$this->dispatch( 'GET', '/status/' . $opened['data']['attempt'] );
		$this->assertSame( 'rejected', $this->attempt_row( $opened['data']['attempt'] )['status'] );

		$expired = $this->open_attempt();
		$this->backdate( $expired['data']['attempt'], array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ) );
		$this->attest( $expired['row'] );
		$this->assertSame( 'expired', $this->attempt_row( $expired['data']['attempt'] )['status'] );
	}

	public function test_authenticate_refusal_happens_before_consumption_and_cookie(): void {
		$user = self::factory()->user->create();
		$this->link_subject( $user );
		$opened = $this->open_attempt();
		$id     = $opened['data']['attempt'];
		$this->attest( $opened['row'] );
		$seen = false;
		add_filter(
			'authenticate',
			function () use ( $id, &$seen ) {
				$seen = true;
				$this->assertSame( 'verified', $this->attempt_row( $id )['status'] );
				$this->assertSame( array(), $this->auth_cookie_users() );
				return new \WP_Error( 'blocked', 'Blocked' );
			},
			99
		);
		$this->assert_http( 403, $this->complete( $id ) );
		$this->assertTrue( $seen );
		$this->assertSame( 'failed', $this->attempt_row( $id )['status'] );
		$this->assertSame( array(), $this->auth_cookie_users() );
	}

	public function test_cookie_is_only_issued_after_consumption(): void {
		$user = self::factory()->user->create();
		$this->link_subject( $user );
		$opened = $this->open_attempt();
		$id     = $opened['data']['attempt'];
		$this->attest( $opened['row'] );
		$seen = false;
		add_action(
			'set_auth_cookie',
			function () use ( $id, &$seen ): void {
				$seen = true;
				$this->assertSame( 'consumed', $this->attempt_row( $id )['status'] );
			}
		);
		$this->assert_http( 200, $this->complete( $id ) );
		$this->assertTrue( $seen );
	}

	public function test_losing_the_consume_race_never_issues_a_cookie(): void {
		$user = self::factory()->user->create();
		$this->link_subject( $user );
		$opened = $this->open_attempt();
		$id     = $opened['data']['attempt'];
		$this->attest( $opened['row'] );
		add_filter(
			'authenticate',
			static function ( $user ) use ( $id ) {
				$repo = Plugin::instance()->attempts();
				$repo->transition( $repo->find_by_public_id( $id ), AttemptStatus::Consumed );
				return $user;
			},
			99
		);
		$this->assert_http( 409, $this->complete( $id ) );
		$this->assertSame( array(), $this->auth_cookie_users() );
		$this->assertSame( 0, get_current_user_id() );
	}

	public function test_provision_filter_cannot_update_an_existing_account(): void {
		$victim = self::factory()->user->create(
			array(
				'display_name' => 'Original',
				'role'         => 'administrator',
			)
		);
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		add_filter(
			'bloclabs_ssi_provision_user_data',
			static function ( $data ) use ( $victim ) {
				$data['ID']           = $victim;
				$data['user_level']   = 10;
				$data['role']         = 'administrator';
				$data['display_name'] = 'Changed';
				return $data;
			}
		);
		$opened = $this->open_attempt();
		$this->attest( $opened['row'] );
		$this->assert_http( 200, $this->complete( $opened['data']['attempt'] ) );
		$this->assertNotSame( $victim, get_current_user_id() );
		$this->assertFalse( current_user_can( 'manage_options' ) );
		$this->assertSame( 'Original', get_userdata( $victim )->display_name );
		$this->assertContains( 'administrator', get_userdata( $victim )->roles );
	}
}
