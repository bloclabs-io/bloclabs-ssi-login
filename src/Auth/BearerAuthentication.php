<?php
/**
 * Authenticates REST requests that carry an application token (ADR 0007 §4, "Use").
 *
 * `Authorization: Bearer bssi_…` on a `/wp-json/` request over HTTPS. The
 * `determine_current_user` filter sits at priority 20, where Application
 * Passwords sit, finds the row by the token's SHA-256 and refuses an expired
 * or revoked token, a missing user, or a request that is not a REST request
 * over HTTPS. A bearer value that is not ours is left to whatever plugin
 * issued it. Once a request carries one of our tokens, the token decides:
 * a refused token never falls back to a cookie or to anonymous, and answers
 * 401 through `rest_authentication_errors` (A1, A8); a valid one skips the
 * cookie nonce check, as Application Passwords do. The token is a header or
 * nothing: never a query argument, never a cookie, so no cross-site page can
 * attach it and no nonce is needed. It is not accepted on wp-admin,
 * wp-login.php, admin-ajax.php or XML-RPC, which are not REST endpoints.
 *
 * Routes that only check for a logged-in user can tell a token request from
 * a session with current() (A13).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Auth;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Login\AgentToken;

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
		add_filter( 'determine_current_user', array( $this, 'authenticate' ), 20 );
		add_filter( 'rest_authentication_errors', array( $this, 'check_errors' ), 90 );
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
	 * `determine_current_user`: the token's user, 0 for a refused token, or whatever
	 * the earlier filters found when the request carries none of our tokens.
	 *
	 * @param int|false $user_id
	 * @return int|false
	 */
	public function authenticate( $user_id ) {
		$token = self::bearer( $_SERVER );
		if ( null === $token || ! AgentToken::is_token( $token ) ) {
			return $user_id;
		}
		$hash = AgentToken::hash( $token );

		if ( ! wp_is_rest_endpoint() ) {
			return $this->refuse( 'not_rest', $hash );
		}
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
		if ( ! get_userdata( $record->user_id ) instanceof \WP_User ) {
			return $this->refuse( 'no_user', $hash );
		}

		if ( null === $record->last_used_at || $record->last_used_at <= $now - self::TOUCH_INTERVAL ) {
			$this->tokens->touch( $record, $now );
		}
		self::$current = $record;
		self::$refusal = null;
		return $record->user_id;
	}

	/**
	 * `rest_authentication_errors`: 401 for a refused token; true for an
	 * accepted one, so the cookie check does not demand a nonce.
	 *
	 * @param \WP_Error|true|null $result
	 * @return \WP_Error|true|null
	 */
	public function check_errors( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}
		if ( null !== self::$refusal ) {
			rest_get_server()->send_header( 'WWW-Authenticate', 'Bearer error="invalid_token"' );
			return self::$refusal;
		}
		if ( null !== self::$current ) {
			return true;
		}
		return $result;
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

	/**
	 * One answer for every refusal (the reason goes to the action, not to the
	 * client): the request is nobody's, whatever cookie it also carried.
	 */
	private function refuse( string $reason, string $token_hash ): int {
		self::$current = null;
		self::$refusal = new \WP_Error( 'bloclabs_ssi_token_refused', __( 'The application token was not accepted.', 'bloclabs-ssi-login' ), array( 'status' => 401 ) );

		/**
		 * An application token was refused.
		 *
		 * @param string $reason     `not_rest`, `not_https`, `unknown`, `revoked`, `expired` or `no_user`.
		 * @param string $token_hash The SHA-256 of the presented token; the token itself is never passed.
		 */
		do_action( 'bloclabs_ssi_agent_token_refused', $reason, $token_hash );

		return 0;
	}
}
