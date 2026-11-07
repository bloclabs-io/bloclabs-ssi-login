<?php
/**
 * Confines a request authenticated by an application token to its scope
 * (ADR 0007 §4, "Scope"; threat A4).
 *
 * Two layers, both only for the token's own user and only while a token is
 * current:
 *
 * - `map_meta_cap` is the enforcement. It answers `do_not_allow` for every
 *   primitive capability the scope does not list, for anything on the
 *   denylist, and for the account's self-service meta capabilities
 *   (`edit_user`, `delete_user`, `promote_user` and the Application Password
 *   ones), which WordPress otherwise grants a user on themselves with no
 *   primitive capability to check: without this an agent with any scope
 *   could change the principal's password or e-mail, or mint an unscoped,
 *   non-expiring Application Password. It has to be this filter: on multisite
 *   `WP_User::has_cap()` grants a super administrator everything before
 *   `user_has_cap` runs, and only `do_not_allow` from `map_meta_cap` stops it.
 * - `user_has_cap` intersects the account's capabilities with the scope's for
 *   everyone else. It can only narrow: a scope never grants what the account
 *   lacks, and a demoted account's agents are demoted with it, on their next
 *   request (A10).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Auth;

use BlocLabs\SsiLogin\Login\Scope;

final class ScopeEnforcement {

	/**
	 * Meta capabilities WordPress grants a user on their own account without a
	 * primitive capability behind them. Never for a token.
	 */
	public const SELF_SERVICE = array(
		'edit_user',
		'delete_user',
		'promote_user',
		'create_app_password',
		'list_app_passwords',
		'read_app_password',
		'edit_app_password',
		'delete_app_password',
		'delete_app_passwords',
	);

	/** Granted to everyone by WP_User::has_cap() after the filter; never withheld. */
	private const ALWAYS = array( 'exist' );

	public function register(): void {
		// Last, so nothing registered later can remove the do_not_allow.
		add_filter( 'map_meta_cap', array( $this, 'map_meta_cap' ), PHP_INT_MAX, 3 );
		add_filter( 'user_has_cap', array( $this, 'user_has_cap' ), PHP_INT_MAX, 4 );
	}

	/**
	 * @param string[] $caps    Primitive capabilities required for $cap.
	 * @param int      $user_id
	 * @return string[]
	 */
	public function map_meta_cap( $caps, string $cap, $user_id ): array {
		$caps  = is_array( $caps ) ? $caps : array();
		$token = BearerAuthentication::current();
		if ( null === $token || (int) $user_id !== $token->user_id || in_array( 'do_not_allow', $caps, true ) ) {
			return $caps;
		}
		if ( in_array( $cap, self::SELF_SERVICE, true ) ) {
			$caps[] = 'do_not_allow';
			return $caps;
		}
		$allowed = self::allowed( $token );
		foreach ( $caps as $primitive ) {
			if ( ! is_string( $primitive ) || ! isset( $allowed[ $primitive ] ) || Scope::is_denied( $primitive ) ) {
				$caps[] = 'do_not_allow';
				return $caps;
			}
		}
		return $caps;
	}

	/**
	 * @param array<string, bool> $allcaps The user's capabilities.
	 * @param string[]            $caps    Primitive capabilities being checked.
	 * @param array<int, mixed>   $args
	 * @return array<string, bool>
	 */
	public function user_has_cap( $allcaps, $caps, $args, \WP_User $user ): array { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed -- filter signature.
		$allcaps = is_array( $allcaps ) ? $allcaps : array();
		$token   = BearerAuthentication::current();
		if ( null === $token || $user->ID !== $token->user_id ) {
			return $allcaps;
		}
		return array_intersect_key( $allcaps, self::allowed( $token ) );
	}

	/**
	 * @return array<string, true> The capabilities a token may exercise, as keys.
	 */
	private static function allowed( TokenRecord $token ): array {
		$allowed = array();
		foreach ( array_merge( Scope::capabilities( $token->scope ), self::ALWAYS ) as $capability ) {
			if ( ! Scope::is_denied( $capability ) ) {
				$allowed[ $capability ] = true;
			}
		}
		return $allowed;
	}
}
