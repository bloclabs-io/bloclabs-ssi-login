<?php
/**
 * Binds a login attempt to the browser that started it.
 *
 * The browser gets a random secret in an HttpOnly, SameSite=Strict cookie;
 * the attempt stores only its SHA-256. Knowing an attempt's public_id is not
 * enough to poll it or complete it: the cookie must come along.
 *
 * Why not WordPress nonces? For logged-out visitors every nonce is computed
 * for user 0 with an empty session token, so all anonymous visitors share it
 * within a tick. It shows the request came from a page we rendered; it binds
 * nothing to a browser. See docs/SECURITY-MODEL.md.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Session;

use BlocLabs\SsiLogin\Config\Settings;

final class BrowserBinding {

	public function __construct( private readonly Settings $settings ) {}

	/**
	 * Issues a new secret cookie and returns the hash to store with the attempt.
	 *
	 * @throws \RuntimeException When the cookie cannot be sent (output already started).
	 */
	public function issue(): string {
		if ( headers_sent() ) {
			throw new \RuntimeException( 'Cannot bind the login attempt: headers already sent.' );
		}

		$secret = rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- base64url of random bytes.

		$this->set_cookie( $secret, time() + $this->settings->int( 'attempt_ttl' ) + 60 );
		$_COOKIE[ $this->cookie_name() ] = $secret;

		return hash( 'sha256', $secret );
	}

	public function matches( Attempt $attempt ): bool {
		$secret = isset( $_COOKIE[ $this->cookie_name() ] ) ? (string) $_COOKIE[ $this->cookie_name() ] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared as an opaque token, never output.
		if ( '' === $secret ) {
			return false;
		}
		return hash_equals( $attempt->binding_hash, hash( 'sha256', $secret ) );
	}

	public function clear(): void {
		$this->set_cookie( '', time() - YEAR_IN_SECONDS );
		unset( $_COOKIE[ $this->cookie_name() ] );
	}

	/**
	 * `__Host-` pins the cookie to this exact host, HTTPS and path "/". The
	 * site counts as HTTPS when its home URL is, even behind a TLS proxy that
	 * hides it from PHP. Plain-HTTP sites (local development) cannot use the prefix.
	 */
	public function cookie_name(): string {
		return $this->settings->site_is_https() ? '__Host-bloclabs_ssi' : 'bloclabs_ssi';
	}

	private function set_cookie( string $value, int $expires ): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			$this->cookie_name(),
			$value,
			array(
				'expires'  => $expires,
				'path'     => '/',
				'secure'   => $this->settings->site_is_https(),
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}
}
