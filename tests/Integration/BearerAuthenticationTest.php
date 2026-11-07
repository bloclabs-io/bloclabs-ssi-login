<?php
/**
 * Bearer authentication of REST requests with an application token (ADR 0007 §4 "Use"; #91).
 *
 * The sequence under test is WordPress's own: the user is determined at
 * bootstrap (`WP::init()`, before REST routing, `wp_is_rest_endpoint()` false),
 * then `WP_REST_Server::check_authentication()` runs for a REST request. No
 * test pretends to be a REST request before that point.
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
	 * Bootstrap: `determine_current_user` runs afresh, as `WP::init()` makes it, before REST routing.
	 */
	private function determine(): int {
		global $current_user;
		$current_user = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- forces core to determine the user again.
		$this->assertFalse( wp_is_rest_endpoint(), 'at bootstrap WordPress does not know this is a REST request' );
		return wp_get_current_user()->ID;
	}

	/**
	 * The REST boundary: what WP_REST_Server::serve_request() asks before dispatching.
	 *
	 * @return \WP_Error|true|null
	 */
	private function rest_authentication() {
		return rest_get_server()->check_authentication();
	}

	/**
	 * The whole sequence for a REST request, as a real one runs it.
	 *
	 * @return \WP_Error|true|null
	 */
	private function serve() {
		$this->determine();
		return $this->rest_authentication();
	}

	public function test_a_valid_token_authenticates_the_rest_request_as_its_user(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$token   = $this->tokens->mint( $user_id, array( 'content' ) );
		$this->present( $token );

		$this->assertSame( 0, $this->determine(), 'at bootstrap the request is nobody\'s: the token is not checked yet' );
		$this->assertNull( BearerAuthentication::current() );
		$this->assertSame( 0, $this->tokens->finds, 'nothing is decided before REST routing' );

		$this->assertTrue( $this->rest_authentication(), 'accepted: no cookie nonce is demanded' );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertNotNull( BearerAuthentication::current() );
		$this->assertSame( AgentToken::hash( $token ), BearerAuthentication::current()->token_hash );
		$this->assertSame( array( 'content' ), BearerAuthentication::current()->scope );
		$this->assertSame( array(), $this->refusals );
		$this->assertCount( 1, $this->tokens->touched, 'first use is recorded' );
		$this->assertSame( array(), $this->auth_cookie_users(), 'a token never turns into a cookie' );
	}

	public function test_a_dispatched_rest_request_sees_the_token_user(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->present( $this->tokens->mint( $user_id, array( 'read' ) ) );
		$this->assertTrue( $this->serve() );

		$response = rest_do_request( new \WP_REST_Request( 'GET', '/wp/v2/users/me' ) );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( $user_id, $response->get_data()['id'] );
	}

	public function test_outside_rest_the_token_is_never_checked_and_the_request_is_nobody_s(): void {
		$cookie_user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		add_filter( 'determine_current_user', static fn () => $cookie_user, 10 );
		$this->present( $this->tokens->mint( $cookie_user, array( 'read' ) ) );

		// wp-admin, wp-login.php, admin-ajax.php, XML-RPC: bootstrap runs, REST authentication never does.
		$this->assertSame( 0, $this->determine(), 'not the cookie user: a request that carries our token is a token request' );
		$this->assertFalse( is_user_logged_in() );
		$this->assertNull( BearerAuthentication::current() );
		$this->assertSame( 0, $this->tokens->finds, 'the table is not asked' );
		$this->assertSame( array(), $this->refusals, 'nothing was refused either: nothing was decided' );
	}

	public function test_last_used_is_written_at_most_once_a_minute(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$recent  = $this->tokens->mint( $user_id, array( 'read' ), array( 'last_used_at' => time() - 30 ) );
		$this->present( $recent );
		$this->assertTrue( $this->serve() );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertSame( array(), $this->tokens->touched, 'used half a minute ago: not written again' );

		BearerAuthentication::reset();
		$stale = $this->tokens->mint( $user_id, array( 'read' ), array( 'last_used_at' => time() - 61 ) );
		$this->present( $stale );
		$this->assertTrue( $this->serve() );
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
		$this->assertNull( $this->rest_authentication(), 'nothing to say: core decides' );
		$this->assertSame( 0, $this->tokens->finds );

		$this->present( base64_encode( 'ada:secret' ), 'Basic' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- a Basic credential, as a test value.
		$this->assertSame( $cookie_user, $this->determine(), 'Basic is Application Passwords\' scheme, not ours' );
		$this->assertNull( $this->rest_authentication() );
		$this->assertSame( array(), $this->refusals );
	}

	public function test_our_token_is_a_header_or_nothing(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$token   = $this->tokens->mint( $user_id );

		// Core answers true for an anonymous request without a nonce; the token in the wrong place changes nothing.
		$_GET['access_token'] = $token;
		$this->assertTrue( $this->serve(), 'not in the query string' );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertNull( BearerAuthentication::current() );
		unset( $_GET['access_token'] );

		$_COOKIE['bssi'] = $token;
		$this->assertTrue( $this->serve(), 'not as a cookie' );
		$this->assertSame( 0, get_current_user_id() );
		unset( $_COOKIE['bssi'] );

		$this->present( $token, 'Token' );
		$this->assertTrue( $this->serve(), 'not under another scheme' );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( 0, $this->tokens->finds, 'none of these was even looked up' );
		$this->assertSame( array(), $this->refusals, 'nor refused: they are not ours' );

		$_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		$this->assertTrue( $this->serve(), 'the header as Apache CGI hands it over' );
		$this->assertSame( $user_id, get_current_user_id() );
	}

	public function test_an_unknown_token_is_refused_and_never_falls_back_to_the_cookie(): void {
		$cookie_user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		add_filter( 'determine_current_user', static fn () => $cookie_user, 10 );
		$token = AgentToken::generate();
		$this->present( $token );

		$error = $this->serve();
		$this->assertInstanceOf( \WP_Error::class, $error );
		$this->assertSame( 'bloclabs_ssi_token_refused', $error->get_error_code() );
		$this->assertSame( 401, $error->get_error_data()['status'] );
		$this->assertSame( 0, get_current_user_id(), 'the request is nobody\'s, cookie or not' );
		$this->assertNull( BearerAuthentication::current() );
		$this->assertSame( array( array( 'unknown', AgentToken::hash( $token ) ) ), $this->refusals );
		$this->assertStringNotContainsString( $token, (string) wp_json_encode( $this->refusals ), 'the action gets the hash, never the token' );
		$this->assertSame( $error, $this->rest_authentication(), 'asked twice, the same answer' );
	}

	public function test_a_valid_token_wins_over_a_cookie_for_another_user(): void {
		$cookie_user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$token_user  = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		add_filter( 'determine_current_user', static fn () => $cookie_user, 10 );
		$this->present( $this->tokens->mint( $token_user ) );

		$this->assertTrue( $this->serve() );
		$this->assertSame( $token_user, get_current_user_id(), 'a request that carries our token is a token request' );
	}

	public function test_expired_and_revoked_tokens_and_deleted_users_are_refused(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->present( $this->tokens->mint( $user_id, array( 'read' ), array( 'expires_at' => time() - 1 ) ) );
		$this->assertInstanceOf( \WP_Error::class, $this->serve() );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( 'expired', $this->refusals[0][0] );

		BearerAuthentication::reset();
		$this->present( $this->tokens->mint( $user_id, array( 'read' ), array( 'revoked_at' => time() - 5 ) ) );
		$this->assertInstanceOf( \WP_Error::class, $this->serve() );
		$this->assertSame( 'revoked', $this->refusals[1][0] );

		BearerAuthentication::reset();
		$this->present( $this->tokens->mint( 987654, array( 'read' ) ) );
		$this->assertInstanceOf( \WP_Error::class, $this->serve() );
		$this->assertSame( 'no_user', $this->refusals[2][0] );
		$this->assertSame( array(), $this->tokens->touched, 'a refused token is not marked used' );
	}

	public function test_the_token_is_only_accepted_over_https(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->present( $this->tokens->mint( $user_id ) );

		unset( $_SERVER['HTTPS'] );
		$this->assertStringStartsWith( 'http://', home_url( '/' ), 'the test site is plain HTTP' );
		$this->assertInstanceOf( \WP_Error::class, $this->serve() );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( 'not_https', $this->refusals[0][0] );
		$this->assertSame( 0, $this->tokens->finds, 'refused before the table is asked' );

		BearerAuthentication::reset();
		update_option( 'home', 'https://example.org' );
		$this->assertTrue( $this->serve(), 'an HTTPS home URL counts, even behind a TLS proxy that hides HTTPS from PHP' );
		$this->assertSame( $user_id, get_current_user_id() );
	}

	public function test_plain_http_is_allowed_only_where_the_environment_is_local(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->present( $this->tokens->mint( $user_id ) );
		unset( $_SERVER['HTTPS'] );
		$this->assertNotSame( 'local', wp_get_environment_type(), 'the test site is not a local environment' );

		$seen = array();
		add_filter(
			'bloclabs_ssi_agent_token_requires_https',
			static function ( bool $requires ) use ( &$seen ): bool {
				$seen[] = $requires;
				return false;
			}
		);
		$this->assertTrue( $this->serve(), 'a local stack without TLS may use tokens, as core allows Application Passwords' );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertSame( array( true ), $seen, 'the default outside a local environment is to require HTTPS' );
	}

	/**
	 * The account's vetoes run on every request (AGENTS.md: no login path skips
	 * `authenticate` / `wp_authenticate_user`), so a lockout or ban set after the
	 * token was issued cuts the agent off at once.
	 */
	public function test_an_account_vetoed_by_wp_authenticate_user_is_refused(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$token   = $this->tokens->mint( $user_id, array( 'content' ) );
		$seen    = array();
		add_filter(
			'wp_authenticate_user',
			static function ( $user, $password ) use ( &$seen ) {
				$seen[] = array( $user->ID, $password );
				return new \WP_Error( 'locked_out', 'Too many failed attempts.' );
			},
			10,
			2
		);
		$this->present( $token );

		$error = $this->serve();
		$this->assertInstanceOf( \WP_Error::class, $error );
		$this->assertSame( 401, $error->get_error_data()['status'] );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertNull( BearerAuthentication::current() );
		$this->assertSame( array( array( $user_id, '' ) ), $seen, 'the filter saw the account, with no password, as a credential login applies it' );
		$this->assertSame( array( array( 'vetoed', AgentToken::hash( $token ) ) ), $this->refusals );
		$this->assertSame( array(), $this->tokens->touched, 'a vetoed request is not a use' );
	}

	public function test_an_account_vetoed_by_authenticate_is_refused_and_a_substituted_user_too(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$other   = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->present( $this->tokens->mint( $user_id, array( 'content' ) ) );

		$veto = static fn () => new \WP_Error( 'banned', 'This account is banned.' );
		add_filter( 'authenticate', $veto, 50 );
		$this->assertInstanceOf( \WP_Error::class, $this->serve() );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( 'vetoed', $this->refusals[0][0] );
		remove_filter( 'authenticate', $veto, 50 );

		BearerAuthentication::reset();
		$swap = static fn () => get_userdata( $other );
		add_filter( 'authenticate', $swap, 50 );
		$this->assertInstanceOf( \WP_Error::class, $this->serve(), 'a filter answering another user is a refusal, not a switch' );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( 'vetoed', $this->refusals[1][0] );
		remove_filter( 'authenticate', $swap, 50 );

		BearerAuthentication::reset();
		$this->assertTrue( $this->serve(), 'without a veto the same token is accepted' );
		$this->assertSame( $user_id, get_current_user_id() );
	}

	public function test_a_token_request_is_not_a_login_attempt(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->present( $this->tokens->mint( $user_id, array( 'content' ) ) );
		$fired = array();
		add_action(
			'wp_authenticate',
			static function () use ( &$fired ): void {
				$fired[] = 'wp_authenticate';
			}
		);
		add_action(
			'wp_login',
			static function () use ( &$fired ): void {
				$fired[] = 'wp_login';
			}
		);
		add_action(
			'wp_login_failed',
			static function () use ( &$fired ): void {
				$fired[] = 'wp_login_failed';
			}
		);

		$this->assertTrue( $this->serve() );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertSame( array(), $fired, 'using a token is neither a login attempt nor a login: the attempt was at issuance' );
	}

	public function test_a_spammed_account_on_multisite_is_refused(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'the spam flag is a multisite user status' );
		}
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->present( $this->tokens->mint( $user_id, array( 'content' ) ) );
		$this->assertTrue( $this->serve(), 'accepted while the account is in good standing' );

		BearerAuthentication::reset();
		wp_update_user(
			array(
				'ID'   => $user_id,
				'spam' => 1,
			)
		);
		$this->assertInstanceOf( \WP_Error::class, $this->serve(), 'core\'s wp_authenticate_spam_check on `authenticate` refuses' );
		$this->assertSame( 0, get_current_user_id() );
		$this->assertSame( 'vetoed', $this->refusals[0][0] );
	}
}
