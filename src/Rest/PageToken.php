<?php
/**
 * A cross-site request token for the login page, independent of the user.
 *
 * wp_create_nonce() binds to the current user, but a REST request that has
 * a login cookie and no X-WP-Nonce header runs as user 0. A logged-in visitor
 * on wp-login.php (reauthentication, interim login) would therefore always
 * fail a regular nonce. This token is what wp_create_nonce() computes for a
 * logged-out visitor: the same for every browser, valid for 12–24 hours. It
 * proves the request came from a page this site rendered; BrowserBinding
 * ties attempts to browsers.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

final class PageToken {

	private const ACTION = 'bloclabs_ssi_login_page';

	public static function create(): string {
		return self::compute( (int) wp_nonce_tick( self::ACTION ) );
	}

	public static function verify( string $token ): bool {
		if ( '' === $token ) {
			return false;
		}
		$tick = (int) wp_nonce_tick( self::ACTION );
		// Current half-day, or the previous one: the same window as WordPress nonces.
		return hash_equals( self::compute( $tick ), $token ) || hash_equals( self::compute( $tick - 1 ), $token );
	}

	private static function compute( int $tick ): string {
		return substr( wp_hash( $tick . '|' . self::ACTION . '|0|', 'nonce' ), -12, 10 );
	}
}
