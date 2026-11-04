<?php
/**
 * POST /complete inside WordPress.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Plugin;
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

	/**
	 * Lockout, ban and disabled-account plugins refuse from `wp_authenticate_user`
	 * (or the `wp_authenticate` action), which core applies only inside its
	 * password callbacks. The finalizer must reach them itself (#28).
	 */
	public function test_a_lockout_on_wp_authenticate_user_refuses_the_login(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );
		$this->reset_auth_cookies();

		$seen = array();
		add_action(
			'wp_authenticate',
			static function ( $login ) use ( &$seen ): void {
				$seen[] = 'wp_authenticate:' . $login;
			}
		);
		add_filter(
			'wp_authenticate_user',
			static function ( $user, $password ) use ( &$seen ) {
				$seen[] = 'wp_authenticate_user:' . ( $user instanceof \WP_User ? $user->ID : '?' ) . ':' . $password;
				return new \WP_Error( 'too_many_retries', 'Too many failed login attempts.' );
			},
			10,
			2
		);
		add_filter(
			'authenticate',
			static function ( $user ) use ( &$seen ) {
				$seen[] = 'authenticate';
				return $user;
			},
			30
		);

		$response = $this->complete( $public_id );

		$this->assert_http( 403, $response );
		$this->assertSame( 'too_many_retries', $this->error_code( $response ) );
		$this->assertSame(
			array( 'wp_authenticate:' . get_userdata( $user_id )->user_login, 'wp_authenticate_user:' . $user_id . ':' ),
			$seen,
			'the lockout refuses before the authenticate filter runs'
		);
		$this->assertSame( 'failed', $this->attempt_row( $public_id )['status'] );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( array(), $this->auth_cookie_users() );
		$this->assertInstanceOf( \WP_User::class, get_userdata( $user_id ) );
	}

	/**
	 * Core reads the auth cookie it picks by is_ssl(). Behind a TLS proxy that
	 * hides HTTPS from PHP the home URL is https while is_ssl() is false, and a
	 * cookie set by the home URL's scheme is never read (#29).
	 */
	public function test_the_auth_cookie_follows_is_ssl_not_the_home_url(): void {
		add_filter( 'home_url', static fn ( $url ) => str_replace( 'http://', 'https://', (string) $url ) );
		$this->assertFalse( is_ssl() );
		$this->assertTrue( Plugin::instance()->settings()->site_is_https() );

		$schemes = array();
		add_action(
			'set_auth_cookie',
			static function ( $cookie, $expire, $expiration, $user_id, $scheme ) use ( &$schemes ): void {
				$schemes[] = $scheme;
			},
			10,
			5
		);

		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 200, $response );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertSame( array( 'auth' ), $schemes, 'the cookie core will read on a plain-HTTP request' );
	}

	/**
	 * The resolve filter's refusal must not leave the account provisioned for it (#29).
	 */
	public function test_a_resolve_user_refusal_removes_the_provisioned_account(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		add_filter( 'bloclabs_ssi_resolve_user', '__return_null' );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 403, $response );
		$this->assertSame( 'bloclabs_ssi_not_linked', $this->error_code( $response ) );
		$this->assertSame( 'failed', $this->attempt_row( $public_id )['status'] );
		$this->assertFalse( get_user_by( 'login', $this->provisioned_login() ), 'the account is gone' );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ), 'and so is the link' );
		$this->assertSame( 0, get_current_user_id() );
	}

	public function test_a_resolve_user_redirect_removes_the_provisioned_account(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		$other = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		add_filter( 'bloclabs_ssi_resolve_user', static fn () => $other );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 200, $response );
		$this->assertSame( $other, get_current_user_id() );
		$this->assertFalse( get_user_by( 'login', $this->provisioned_login() ) );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	/**
	 * wpdb refuses an over-length value before any SQL, so with a varchar(191)
	 * issuer column a long did:jwk issuer failed the link, deleted the new account
	 * and refused every login of that subject as "not linked" (#29).
	 */
	public function test_a_long_issuer_id_is_stored_with_the_link(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		$issuer                          = 'did:jwk:' . str_repeat( 'eyJrdHkiOiJSU0EiLCJuIjoi', 25 );
		VerifierFake::instance()->issuer = $issuer;
		$this->assertGreaterThan( 191, strlen( $issuer ) );
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 200, $response );
		$this->assertGreaterThan( 0, get_current_user_id() );
		$this->assertSame( $issuer, $this->stored_issuer() );
	}

	/**
	 * The login is deterministic, so an unlinked account with this subject's
	 * login belongs to a concurrent request that has not linked it yet: the
	 * browser retries instead of hearing "not linked" (#29).
	 */
	public function test_an_unlinked_account_with_the_subjects_login_means_retry(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		$racer     = self::factory()->user->create(
			array(
				'user_login' => $this->provisioned_login(),
				'role'       => 'subscriber',
			)
		);
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->attest( $opened['row'] );

		$response = $this->complete( $public_id );

		$this->assert_http( 503, $response );
		$this->assertSame( 'bloclabs_ssi_retry', $this->error_code( $response ) );
		$this->assertSame( 'verified', $this->attempt_row( $public_id )['status'] );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertInstanceOf( \WP_User::class, get_userdata( $racer ), 'the other request\'s account is left alone' );

		// Once that request has linked it, the retry logs in as it.
		$this->link_subject( $racer );
		$again = $this->complete( $public_id );
		$this->assert_http( 200, $again );
		$this->assertSame( $racer, get_current_user_id() );
	}

	private function provisioned_login(): string {
		return 'ssi-' . substr( $this->subject_hash(), 0, 12 );
	}

	private function stored_issuer(): ?string {
		global $wpdb;
		$table  = \BlocLabs\SsiLogin\Database\Schema::identities_table();
		$issuer = $wpdb->get_var( $wpdb->prepare( "SELECT issuer FROM {$table} WHERE subject_hash = %s", $this->subject_hash() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return is_string( $issuer ) ? $issuer : null;
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
