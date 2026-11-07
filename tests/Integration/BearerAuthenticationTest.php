<?php
/**
 * Bearer authentication of REST requests with an application token (ADR 0007 §4 "Use"; #91).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Auth\BearerAuthentication;
use BlocLabs\SsiLogin\Auth\ScopeEnforcement;
use BlocLabs\SsiLogin\Login\AgentToken;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Tests\Integration\Support\TokenLookupFake;

final class BearerAuthenticationTest extends IntegrationTestCase {

	private TokenLookupFake $tokens;

	/** @var list<array{0: string, 1: string}> */
	private array $refusals = array();

	protected function setUp(): void {
		parent::setUp();
		$this->tokens   = new TokenLookupFake();
		$this->refusals = array();
		( new BearerAuthentication( Plugin::instance()->settings(), $this->tokens, new ScopeEnforcement() ) )->register();
		add_action(
			BearerAuthentication::REFUSED,
			function ( string $reason, string $hash ): void {
				$this->refusals[] = array( $reason, $hash );
			},
			10,
			2
		);
		// A REST request over HTTPS, unless a test says otherwise.
		add_filter( 'wp_is_rest_endpoint', '__return_true' );
		$_SERVER['HTTPS'] = 'on';
		BearerAuthentication::reset();
	}

	protected function tearDown(): void {
		unset( $_SERVER['HTTPS'], $_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION'], $_GET['access_token'], $_COOKIE['bssi'] );
		BearerAuthentication::reset();
		parent::tearDown();
	}

	private function present( string $token, string $scheme = 'Bearer' ): void {
		$_SERVER['HTTP_AUTHORIZATION'] = $scheme . ' ' . $token;
	}

	/**
	 * Runs `determine_current_user` afresh, as the first `wp_get_current_user()` of a request does.
	 */
	private function determine(): int {
		global $current_user;
		$current_user = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- forces core to determine the user again.
		return wp_get_current_user()->ID;
	}

	/**
	 * @return \WP_Error|true|null
	 */
	private function rest_authentication() {
		return rest_get_server()->check_authentication();
	}

	public function test_a_valid_token_authenticates_the_rest_request_as_its_user(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$token   = $this->tokens->mint( $user_id, array( 'content' ) );
		$this->present( $token );

		$this->assertSame( $user_id, $this->determine() );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertNotNull( BearerAuthentication::current() );
		$this->assertSame( AgentToken::hash( $token ), BearerAuthentication::current()->token_hash );
		$this->assertSame( array( 'content' ), BearerAuthentication::current()->scope );
		$this->assertTrue( $this->rest_authentication(), 'accepted: no cookie nonce is demanded' );
		$this->assertSame( array(), $this->refusals );
		$this->assertCount( 1, $this->tokens->touched, 'first use is recorded' );
		$this->assertSame( array(), $this->auth_cookie_users(), 'a token never turns into a cookie' );
	}

	public function test_last_used_is_written_at_most_once_a_minute(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$recent  = $this->tokens->mint( $user_id, array( 'read' ), array( 'last_used_at' => time() - 30 ) );
		$this->present( $recent );
		$this->assertSame( $user_id, $this->determine() );
		$this->assertSame( array(), $this->tokens->touched, 'used half a minute ago: not written again' );

		BearerAuthentication::reset();
		$stale = $this->tokens->mint( $user_id, array( 'read' ), array( 'last_used_at' => time() - 61 ) );
		$this->present( $stale );
		$this->assertSame( $user_id, $this->determine() );
		$this->assertCount( 1, $this->tokens->touched );
		$this->assertSame( AgentToken::hash( $stale ), $this->tokens->touched[0][0]->token_hash );
	}

	public function test_a_request_without_our_token_is_left_to_the_other_filters(): void {
		$cookie_user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		add_filter( 'determine_current_user', static fn () => $cookie_user, 10 );

		$this->assertSame( $cookie_user, $this->determine(), 'no header: the cookie user stands' );
		$this->assertNull( BearerAuthentication::current() );

		$this->present( 'ghp_' . str_repeat( 'a', 44 ) );
		$this->assertSame( $cookie_user, $this->determine(), 'another issuer\'s bearer token is not ours to judge' );
		$this->assertSame( 0, $this->tokens->finds );

		$this->present( base64_encode( 'ada:secret' ), 'Basic' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- a Basic credential, as a test value.
		$this->assertSame( $cookie_user, $this->determine(), 'Basic is Application Passwords\' scheme, not ours' );
		$this->assertSame( array(), $this->refusals );
		$this->assertNull( $this->rest_authentication(), 'nothing to say: core decides' );
	}

	public function test_our_token_is_a_header_or_nothing(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$token   = $this->tokens->mint( $user_id );

		$_GET['access_token'] = $token;
		$this->assertSame( 0, $this->determine(), 'not in the query string' );
		unset( $_GET['access_token'] );

		$_COOKIE['bssi'] = $token;
		$this->assertSame( 0, $this->determine(), 'not as a cookie' );
		unset( $_COOKIE['bssi'] );

		$this->present( $token, 'Token' );
		$this->assertSame( 0, $this->determine(), 'not under another scheme' );
		$this->assertSame( 0, $this->tokens->finds, 'none of these was even looked up' );

		$_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		$this->assertSame( $user_id, $this->determine(), 'the header as Apache CGI hands it over' );
	}

	public function test_an_unknown_token_is_refused_and_never_falls_back_to_the_cookie(): void {
		$cookie_user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		add_filter( 'determine_current_user', static fn () => $cookie_user, 10 );
		$token = AgentToken::generate();
		$this->present( $token );

		$this->assertSame( 0, $this->determine(), 'the request is nobody\'s, cookie or not' );
		$this->assertNull( BearerAuthentication::current() );
		$error = $this->rest_authentication();
		$this->assertInstanceOf( \WP_Error::class, $error );
		$this->assertSame( 'bloclabs_ssi_token_refused', $error->get_error_code() );
		$this->assertSame( 401, $error->get_error_data()['status'] );
		$this->assertSame( array( array( 'unknown', AgentToken::hash( $token ) ) ), $this->refusals );
		$this->assertStringNotContainsString( $token, (string) wp_json_encode( $this->refusals ), 'the action gets the hash, never the token' );
	}

	public function test_a_valid_token_wins_over_a_cookie_for_another_user(): void {
		$cookie_user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$token_user  = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		add_filter( 'determine_current_user', static fn () => $cookie_user, 10 );
		$this->present( $this->tokens->mint( $token_user ) );

		$this->assertSame( $token_user, $this->determine(), 'a request that carries our token is a token request' );
	}

	public function test_expired_and_revoked_tokens_and_deleted_users_are_refused(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->present( $this->tokens->mint( $user_id, array( 'read' ), array( 'expires_at' => time() - 1 ) ) );
		$this->assertSame( 0, $this->determine() );
		$this->assertSame( 'expired', $this->refusals[0][0] );
		$this->assertInstanceOf( \WP_Error::class, $this->rest_authentication() );

		BearerAuthentication::reset();
		$this->present( $this->tokens->mint( $user_id, array( 'read' ), array( 'revoked_at' => time() - 5 ) ) );
		$this->assertSame( 0, $this->determine() );
		$this->assertSame( 'revoked', $this->refusals[1][0] );

		BearerAuthentication::reset();
		$this->present( $this->tokens->mint( 987654, array( 'read' ) ) );
		$this->assertSame( 0, $this->determine() );
		$this->assertSame( 'no_user', $this->refusals[2][0] );
		$this->assertSame( array(), $this->tokens->touched, 'a refused token is not marked used' );
	}

	public function test_the_token_is_only_accepted_on_rest_requests_over_https(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$token   = $this->tokens->mint( $user_id );
		$this->present( $token );

		remove_filter( 'wp_is_rest_endpoint', '__return_true' );
		add_filter( 'wp_is_rest_endpoint', '__return_false' );
		$this->assertSame( 0, $this->determine(), 'wp-admin, wp-login.php, admin-ajax.php: not a REST endpoint' );
		$this->assertSame( 'not_rest', $this->refusals[0][0] );
		remove_filter( 'wp_is_rest_endpoint', '__return_false' );
		add_filter( 'wp_is_rest_endpoint', '__return_true' );

		BearerAuthentication::reset();
		unset( $_SERVER['HTTPS'] );
		$this->assertStringStartsWith( 'http://', home_url( '/' ), 'the test site is plain HTTP' );
		$this->assertSame( 0, $this->determine() );
		$this->assertSame( 'not_https', $this->refusals[1][0] );
		$this->assertSame( 0, $this->tokens->finds, 'refused before the table is asked' );

		BearerAuthentication::reset();
		update_option( 'home', 'https://example.org' );
		$this->assertSame( $user_id, $this->determine(), 'an HTTPS home URL counts, even behind a TLS proxy that hides HTTPS from PHP' );
	}

	public function test_a_dispatched_rest_request_sees_the_token_user(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->present( $this->tokens->mint( $user_id, array( 'read' ) ) );
		$this->determine();

		$response = rest_do_request( new \WP_REST_Request( 'GET', '/wp/v2/users/me' ) );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( $user_id, $response->get_data()['id'] );
		$this->assertTrue( wp_is_rest_endpoint() );
	}
}
