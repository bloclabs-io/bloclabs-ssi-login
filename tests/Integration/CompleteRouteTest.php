<?php
/**
 * POST /complete inside WordPress.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class CompleteRouteTest extends IntegrationTestCase {

	public function test_commitment_mismatch_fails_the_attempt(): void {
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		VerifierFake::instance()->subject_id = 'did:example:other-subject';
		$mismatched                          = false;
		add_action(
			'bloclabs_ssi_commitment_mismatch',
			static function () use ( &$mismatched ): void {
				$mismatched = true;
			}
		);

		$response = $this->complete( $public_id );

		$this->assert_http( 403, $response );
		$this->assertSame( 'bloclabs_ssi_mismatch', $this->error_code( $response ) );
		$this->assertTrue( $mismatched );
		$this->assertSame( 'failed', $this->attempt_row( $public_id )['status'] );
		$this->assertSame( 0, get_current_user_id() );
	}

	public function test_transient_verifier_error_keeps_the_attempt_verified(): void {
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		VerifierFake::instance()->result_error = new VerifierException( 'down', 503 );
		$response                              = $this->complete( $public_id );

		$this->assert_http( 503, $response );
		$this->assertSame( 'bloclabs_ssi_retry', $this->error_code( $response ) );
		$this->assertSame( 'verified', $this->attempt_row( $public_id )['status'] );
		$this->assertSame( 0, get_current_user_id() );
	}

	public function test_unlinked_subject_is_refused_under_link_only(): void {
		$this->configure( array( 'linking_policy' => Settings::LINK_ONLY ) );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 403, $response );
		$this->assertSame( 'bloclabs_ssi_not_linked', $this->error_code( $response ) );
		$this->assertSame( 'failed', $this->attempt_row( $public_id )['status'] );
		$this->assertSame( 0, get_current_user_id() );
	}

	public function test_auto_provision_never_grants_a_role_that_can_manage_the_site(): void {
		$this->configure(
			array(
				'linking_policy' => Settings::AUTO_PROVISION,
				'default_role'   => 'administrator',
			)
		);
		add_filter(
			'bloclabs_ssi_provision_user_data',
			static function ( $data ) {
				if ( is_array( $data ) ) {
					$data['role'] = 'administrator';
				}
				return $data;
			}
		);

		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 200, $response );
		$user = wp_get_current_user();
		$this->assertGreaterThan( 0, $user->ID );
		$this->assertFalse( $user->has_cap( 'manage_options' ) );
		$this->assertFalse( $user->has_cap( 'edit_users' ) );
		$this->assertFalse( $user->has_cap( 'promote_users' ) );
		$this->assertContains( 'subscriber', $user->roles );
		$this->assertSame( 'consumed', $this->attempt_row( $public_id )['status'] );
	}

	public function test_allow_login_false_refuses(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );
		add_filter( 'bloclabs_ssi_allow_login', '__return_false' );

		$response = $this->complete( $public_id );

		$this->assert_http( 403, $response );
		$this->assertSame( 'bloclabs_ssi_refused', $this->error_code( $response ) );
		$this->assertSame( 'failed', $this->attempt_row( $public_id )['status'] );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertInstanceOf( \WP_User::class, get_userdata( $user_id ) );
	}

	public function test_success_sets_the_auth_cookie_and_consumes_the_attempt_once(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$secret    = $this->binding_cookie();
		$this->attest( $opened['row'] );
		$this->reset_auth_cookies();

		$response = $this->complete( $public_id );

		$this->assert_http( 200, $response );
		$this->assertNotSame( '', (string) $response->get_data()['redirect_to'] );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertSame( array( $user_id ), $this->auth_cookie_users() );

		$consumed = $this->attempt_row( $public_id );
		$this->assertSame( 'consumed', $consumed['status'] );
		$this->assertSame( (string) $user_id, (string) $consumed['user_id'] );

		// The finalizer clears the binding cookie. Put it back: the row must still refuse a second login.
		$this->restore_browser( $secret );
		$this->reset_auth_cookies();
		wp_set_current_user( 0 );

		$again = $this->complete( $public_id );

		$this->assert_http( 409, $again );
		$this->assertSame( array(), $this->auth_cookie_users() );
		$this->assertSame( 0, get_current_user_id() );
		$after = $this->attempt_row( $public_id );
		$this->assertSame( 'consumed', $after['status'] );
		$this->assertSame( $consumed['consumed_at'], $after['consumed_at'] );
	}
}
