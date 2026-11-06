<?php
/**
 * Account- and browser-bound credential management through the real REST routes.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Rest\ReturnUrl;
use BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class ProfileCredentialTest extends IntegrationTestCase {

	/** @param array<string, mixed> $params */
	private function profile_request( string $route, array $params = array() ): \WP_REST_Response {
		return $this->dispatch( 'POST', $route, $params, array( 'X-WP-Nonce' => wp_create_nonce( 'wp_rest' ) ) );
	}

	/** @return array<string, mixed> */
	private function start_link(): array {
		$response = $this->profile_request( '/initiate', array( 'purpose' => 'link' ) );
		$this->assert_http( 201, $response );
		$row = $this->attempt_row( $response->get_data()['attempt'] );
		$this->assertSame( 'link', $row['purpose'] );
		$this->assertSame( get_current_user_id(), (int) $row['link_user_id'] );
		return $row;
	}

	public function test_link_unlink_and_link_only_login(): void {
		$owner = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $owner );
		$row = $this->start_link();
		$this->attest( $row );
		$this->reset_auth_cookies();
		$response = $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) );
		$this->assert_http( 200, $response );
		$this->assertSame( array( 'linked' => true ), $response->get_data() );
		$this->assertSame( $owner, get_current_user_id() );
		$this->assertSame( array(), $this->auth_cookie_users() );
		$this->assertSame( $owner, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
		$this->assertSame( 'consumed', $this->attempt_row( $row['public_id'] )['status'] );
		$this->assert_http( 409, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );

		wp_set_current_user( 0 );
		$login = $this->open_attempt();
		$this->attest( $login['row'] );
		$this->assert_http( 200, $this->complete( $login['data']['attempt'] ) );
		$this->assertSame( $owner, get_current_user_id() );

		$identity = Plugin::instance()->identities()->for_user( $owner )[0];
		$this->assert_http( 200, $this->profile_request( '/profile/unlink', array( 'identity' => (int) $identity['id'] ) ) );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
		wp_set_current_user( 0 );
		$login = $this->open_attempt();
		$this->attest( $login['row'] );
		$this->assert_http( 403, $this->complete( $login['data']['attempt'] ) );
	}

	public function test_relink_and_cross_account_subject_are_refused(): void {
		$owner = self::factory()->user->create();
		$this->link_subject( $owner );
		foreach ( array( $owner, self::factory()->user->create() ) as $user_id ) {
			wp_set_current_user( $user_id );
			$row = $this->start_link();
			$this->attest( $row );
			$response = $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) );
			$this->assert_http( 409, $response );
			$this->assertSame( 'bloclabs_ssi_already_linked', $this->error_code( $response ) );
			$this->assertSame( $owner, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
			$this->assertSame( $user_id, get_current_user_id() );
		}
	}

	public function test_switched_account_and_missing_browser_cannot_complete(): void {
		$owner = self::factory()->user->create();
		wp_set_current_user( $owner );
		$row = $this->start_link();
		$this->attest( $row );
		$cookie = $this->binding_cookie();
		wp_set_current_user( self::factory()->user->create() );
		$this->assert_http( 404, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );
		wp_set_current_user( $owner );
		$this->forget_browser();
		$this->assert_http( 404, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );
		$this->restore_browser( $cookie );
		$this->assert_http( 200, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );
	}

	public function test_nonce_login_and_unlink_ownership_are_required(): void {
		$this->assert_http( 403, $this->profile_request( '/initiate', array( 'purpose' => 'link' ) ) );
		$owner = self::factory()->user->create();
		$this->link_subject( $owner );
		$identity = Plugin::instance()->identities()->for_user( $owner )[0];
		wp_set_current_user( $owner );
		$this->assert_http( 403, $this->dispatch( 'POST', '/initiate', array( 'purpose' => 'link' ) ) );
		$this->assert_http( 403, $this->dispatch( 'POST', '/profile/unlink', array( 'identity' => (int) $identity['id'] ) ) );
		wp_set_current_user( self::factory()->user->create() );
		$this->assert_http(
			404,
			$this->profile_request(
				'/profile/unlink',
				array(
					'identity' => (int) $identity['id'],
					'user_id'  => $owner,
				)
			)
		);
		$this->assertSame( $owner, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	public function test_transient_result_retries_and_mismatch_never_links(): void {
		wp_set_current_user( self::factory()->user->create() );
		$row = $this->start_link();
		$this->attest( $row );
		VerifierFake::instance()->result_error = new VerifierException( 'temporary', 503 );
		$this->assert_http( 503, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );
		$this->assertSame( 'verified', $this->attempt_row( $row['public_id'] )['status'] );
		VerifierFake::instance()->result_error = null;
		VerifierFake::instance()->subject_id   = 'did:example:different';
		$this->assert_http( 403, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );
		$this->assertSame( 'failed', $this->attempt_row( $row['public_id'] )['status'] );
		$this->assertSame( array(), Plugin::instance()->identities()->for_user( get_current_user_id() ) );
		$this->assertSame( array(), $this->auth_cookie_users() );
	}

	public function test_profile_only_renders_own_escaped_labels(): void {
		$owner = self::factory()->user->create();
		$this->link_subject( $owner );
		wp_set_current_user( $owner );
		$this->assertTrue( Plugin::instance()->identities()->link( hash( 'sha256', 'other' ), $owner, '<script>unsafe</script>', null ) );
		$screen = new \BlocLabs\SsiLogin\Admin\ProfileScreen( Plugin::instance() );
		ob_start();
		$screen->render( get_userdata( $owner ) );
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Link a credential', $html );
		$this->assertStringContainsString( 'data-ssi-unlink', $html );
		$this->assertStringContainsString( '&lt;script&gt;unsafe&lt;/script&gt;', $html );
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringNotContainsString( (string) \BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent::fixture()['subject'], $html );
		ob_start();
		$screen->render( get_userdata( self::factory()->user->create() ) );
		$this->assertSame( '', ob_get_clean() );
	}

	/**
	 * A link attempt sends a wallet on the holder's own device back to this site's
	 * profile page, naming the attempt (#96); the session and the binding cookie
	 * still decide who may complete it.
	 */
	public function test_a_link_attempt_returns_to_the_profile_page(): void {
		update_option( 'home', 'https://login.example' );
		update_option( 'siteurl', 'https://login.example' );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );

		$row = $this->start_link();

		$this->assertSame(
			'https://login.example/wp-admin/profile.php?' . ReturnUrl::PARAM . '=' . $row['public_id'],
			VerifierFake::instance()->last_request?->return_url
		);
	}

	public function test_expired_attempt_cannot_link(): void {
		wp_set_current_user( self::factory()->user->create() );
		$row = $this->start_link();
		$this->attest( $row );
		$this->backdate( $row['public_id'], array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ) );
		$this->assert_http( 409, $this->profile_request( '/complete', array( 'attempt' => $row['public_id'] ) ) );
		$this->assertSame( array(), Plugin::instance()->identities()->for_user( get_current_user_id() ) );
	}
}
