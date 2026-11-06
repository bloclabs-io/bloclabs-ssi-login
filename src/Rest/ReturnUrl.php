<?php
/**
 * Where a wallet on the holder's own device sends the holder after it presented.
 *
 * A same-device wallet opens the attempt from the page's link and leaves the
 * browser behind; without a way back, the page completes the attempt only once
 * the holder switches to it by hand, and the attempt can expire first (#96).
 * WordPress therefore names the page the attempt started on, with the attempt's
 * public id, and the bridge hands it to the verifier, which answers the wallet's
 * presentation with it as the OpenID4VP `redirect_uri`. The wallet opens it, and
 * the page finishes the attempt as it always did.
 *
 * The URL binds nothing. It is built from the site's own login and profile URLs,
 * never from the request, and names the attempt only by its public id, which is
 * useless without the binding cookie: /status and /complete still require the
 * cookie of the browser that started the attempt, so the URL cannot complete
 * another browser's attempt, and opening it again finds the attempt consumed
 * (docs/SECURITY-MODEL.md, threat 24).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Session\Attempt;

final class ReturnUrl {

	/** Query parameter naming the attempt to finish; the page scripts read it and drop it from the address. */
	public const PARAM = 'bloclabs_ssi_attempt';

	/**
	 * The return URL of an attempt, or null when the site has none the bridge
	 * accepts: wallets open https links, so a plain-http site offers no return
	 * unless it is a localhost test stack (the bridge applies the rule of its
	 * Digital Credentials API origins). Behind a TLS proxy that hides HTTPS from
	 * PHP the scheme follows the home URL, as the binding cookie does.
	 */
	public static function for_attempt( Settings $settings, Attempt $attempt ): ?string {
		// This site's own profile page for a link attempt; the login page, with the redirect
		// validated at /initiate, for a login: an attempt started on a WooCommerce login form
		// returns through wp-login.php too and lands on the Woo page with that redirect.
		// A plugin that moves the login page is honoured through wp_login_url()'s filter.
		$url = 'link' === $attempt->purpose
			? admin_url( 'profile.php' )
			: wp_login_url( (string) $attempt->redirect_to );
		if ( $settings->site_is_https() ) {
			$url = set_url_scheme( $url, 'https' );
		}
		// Always a query, so that the verifier's own "&response_code=…" lands in it well-formed.
		$url = add_query_arg( self::PARAM, $attempt->public_id, $url );

		$scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );
		$host   = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( 'https' === $scheme || ( 'http' === $scheme && self::is_loopback( $host ) ) ) {
			return $url;
		}
		return null;
	}

	private static function is_loopback( string $host ): bool {
		return 'localhost' === $host || str_ends_with( $host, '.localhost' ) || '127.0.0.1' === $host || '[::1]' === $host;
	}
}
