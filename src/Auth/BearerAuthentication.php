<?php
/**
 * Authenticates REST requests that carry an application token (ADR 0007 §4, "Use").
 *
 * `Authorization: Bearer bssi_…` on a `/wp-json/` request over HTTPS. Two
 * filters share the work, because of when WordPress runs them:
 *
 * - `determine_current_user` (priority 20, where Application Passwords sit)
 *   runs at bootstrap, in `WP::init()`, before REST routing has said whether
 *   this is a REST request at all. Nothing about the token can be decided
 *   there, so it only reserves the request: one that carries one of our
 *   tokens is a token request and nobody's until the token is checked. The
 *   cookie it may also carry is not used (A1, A8).
 * - `rest_authentication_errors` (priority 90) fires from
 *   `WP_REST_Server::check_authentication()`, once routing has established a
 *   REST request and before any route runs. That is where the token is
 *   checked: the row by the token's SHA-256, revoked, expired, a missing
 *   user, plain HTTP, and the account's own vetoes (`wp_authenticate_user`
 *   and `authenticate`, on every request, so a lockout or a spam flag cuts an
 *   agent off at once). An accepted token sets the current user and answers
 *   true, so the cookie nonce check stands down as it does for Application
 *   Passwords; a refused one answers 401 and never falls back to a cookie or
 *   to anonymous.
 *
 * Outside REST the second filter never fires, so the token is never checked
 * and the request stays nobody's: wp-admin, wp-login.php, admin-ajax.php and
 * XML-RPC never see a token's user. A bearer value that is not ours is left
 * to whatever plugin issued it. The token is a header or nothing: never a
 * query argument, never a cookie, so no cross-site page can attach it and no
 * nonce is needed.
 *
 * Routes that only check for a logged-in user can tell a token request from
 * a session with current() (A13). `rest_api_init` runs before the token is
 * checked, so routes are registered for an anonymous request, as they are
 * for a cookie session that sent no nonce.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Auth;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Login\AgentToken;
use BlocLabs\SsiLogin\Login\LoginChecks;

final class BearerAuthentication {

	/** Fired once a token refuses; lockout plugins hook it. */
	public const REFUSED = 'bloclabs_ssi_agent_token_refused';

	/** Seconds between two writes of `last_used_at` for one token. */
	public const TOUCH_INTERVAL = 60;

	private static ?TokenRecord $current = null;

	private static ?\WP_Error $refusal = null;

	public function __construct(
		private readonly Settings $settings,
		private readonly TokenLookup $tokens,
		private readonly ScopeEnforcement $scope,
	) {}

	public function register(): void {
		add_filter( 'determine_current_user', array( $this, 'reserve' ), 20 );
		add_filter( 'rest_authentication_errors', array( $this, 'authenticate' ), 90 );
		$this->scope->register();
	}

	/**
	 * The token this request authenticated with, or null for a session, an
	 * anonymous request, or a refused token.
	 */
	public static function current(): ?TokenRecord {
		return self::$current;
	}

	/**
	 * Forgets this request's outcome. Tests only: a request is one process.
	 */
	public static function reset(): void {
		self::$current = null;
		self::$refusal = null;
	}

	/**
	 * `determine_current_user`: nobody, for a request that carries one of our
	 * tokens; whatever the earlier filters found for any other request.
	 *
	 * At bootstrap `REST_REQUEST` is not defined yet, so this cannot know
	 * whether the token will be checked. It decides nothing and records
	 * nothing: authenticate() does, at the REST boundary.
	 *
	 * @param int|false $user_id
	 * @return int|false
	 */
	public function reserve( $user_id ) {
		return null === self::presented() ? $user_id : 0;
	}

	/**
	 * `rest_authentication_errors`: checks the token this REST request carries.
	 * True for an accepted one, with its user made current; a 401 for a
	 * refused one; untouched for a request without one of our tokens.
	 *
	 * @param \WP_Error|true|null $result
	 * @return \WP_Error|true|null
	 */
	public function authenticate( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}
		$token = self::presented();
		if ( null === $token ) {
			return $result;
		}
		// Decided already, should the server ask twice.
		if ( null !== self::$refusal ) {
			return self::$refusal;
		}
		if ( null !== self::$current ) {
			return true;
		}

		$decision = $this->decide( AgentToken::hash( $token ) );
		if ( $decision instanceof \WP_Error ) {
			wp_set_current_user( 0 );
			rest_get_server()->send_header( 'WWW-Authenticate', 'Bearer error="invalid_token"' );
			return $decision;
		}
		wp_set_current_user( $decision->user_id );
		return true;
	}

	/**
	 * The bearer value of the request's Authorization header, or null when
	 * the header is missing or uses another scheme. Apache in CGI mode hands
	 * the header over as REDIRECT_HTTP_AUTHORIZATION, as core knows.
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 */
	public static function bearer( array $server ): ?string {
		$header = $server['HTTP_AUTHORIZATION'] ?? $server['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
		if ( ! is_string( $header ) || 1 !== preg_match( '/^\s*Bearer\s+(\S+)\s*$/i', $header, $m ) ) {
			return null;
		}
		return $m[1];
	}

	/** One of our tokens, as this request presents it, or null. */
	private static function presented(): ?string {
		$token = self::bearer( $_SERVER );
		return null !== $token && AgentToken::is_token( $token ) ? $token : null;
	}

	/**
	 * The row an accepted token stands for, or the refusal. Records the outcome.
	 *
	 * @return TokenRecord|\WP_Error
	 */
	private function decide( string $hash ) {
		if ( ! $this->settings->site_is_https() ) {
			return $this->refuse( 'not_https', $hash );
		}

		$record = $this->tokens->find( $hash );
		if ( null === $record ) {
			return $this->refuse( 'unknown', $hash );
		}
		if ( $record->is_revoked() ) {
			return $this->refuse( 'revoked', $hash );
		}
		$now = time();
		if ( $record->is_expired( $now ) ) {
			return $this->refuse( 'expired', $hash );
		}
		$user = get_userdata( $record->user_id );
		if ( ! $user instanceof \WP_User ) {
			return $this->refuse( 'no_user', $hash );
		}
		// The account's own vetoes, on every request: a lockout, a ban or a spam flag set after issuance cuts the agent off now.
		if ( null !== LoginChecks::check_account( $user ) ) {
			return $this->refuse( 'vetoed', $hash );
		}

		if ( null === $record->last_used_at || $record->last_used_at <= $now - self::TOUCH_INTERVAL ) {
			$this->tokens->touch( $record, $now );
		}
		self::$current = $record;
		self::$refusal = null;
		return $record;
	}

	/**
	 * One answer for every refusal (the reason goes to the action, not to the
	 * client): the request is nobody's, whatever cookie it also carried.
	 */
	private function refuse( string $reason, string $token_hash ): \WP_Error {
		self::$current = null;
		self::$refusal = new \WP_Error( 'bloclabs_ssi_token_refused', __( 'The application token was not accepted.', 'bloclabs-ssi-login' ), array( 'status' => 401 ) );

		/**
		 * An application token was refused.
		 *
		 * @param string $reason     `not_https`, `unknown`, `revoked`, `expired`, `no_user` or `vetoed`
		 *                           (the account failed `wp_authenticate_user` or `authenticate`).
		 * @param string $token_hash The SHA-256 of the presented token; the token itself is never passed.
		 */
		do_action( 'bloclabs_ssi_agent_token_refused', $reason, $token_hash );

		return self::$refusal;
	}
}
