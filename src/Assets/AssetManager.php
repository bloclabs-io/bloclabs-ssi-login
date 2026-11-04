<?php
/**
 * Registers and enqueues the login-screen assets.
 *
 * Nothing loads outside wp-login.php. The QR encoder is a vendored copy of
 * qrcode-generator (MIT), copied in by `npm run vendor`; without it the block
 * still offers the same-device wallet link.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Assets;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Rest\BrowserController;
use BlocLabs\SsiLogin\Rest\PageToken;
use BlocLabs\SsiLogin\Rest\Routes;
use BlocLabs\SsiLogin\Verifier\PresentationOffer;

use const BlocLabs\SsiLogin\PLUGIN_DIR;
use const BlocLabs\SsiLogin\PLUGIN_FILE;
use const BlocLabs\SsiLogin\VERSION;

final class AssetManager {

	public const HANDLE = 'bloclabs-ssi-login';
	public const QR     = 'bloclabs-ssi-qrcode';

	public function __construct( private readonly Settings $settings ) {}

	/** Keep browser REST requests on wp-login.php's origin, including scheme and port. */
	public function rest_base(): string {
		$rest = rest_url( Routes::NAMESPACE . '/' );
		// Match the binding cookie's HTTPS policy when TLS terminates before PHP.
		$scheme = $this->settings->site_is_https() ? 'https' : null;
		$site   = site_url( '', $scheme );
		foreach ( array( PHP_URL_SCHEME, PHP_URL_HOST, PHP_URL_PORT ) as $part ) {
			if ( wp_parse_url( $rest, $part ) !== wp_parse_url( $site, $part ) ) {
				return site_url( 'index.php?rest_route=/' . Routes::NAMESPACE . '/', $scheme );
			}
		}
		return $rest;
	}

	public function enqueue_login(): void {
		$deps = array();
		if ( is_readable( PLUGIN_DIR . '/assets/vendor/qrcode.js' ) ) {
			wp_register_script( self::QR, plugins_url( 'assets/vendor/qrcode.js', PLUGIN_FILE ), array(), '1.4.4', array( 'in_footer' => true ) );
			$deps[] = self::QR;
		}

		wp_enqueue_style( self::HANDLE, plugins_url( 'assets/css/login.css', PLUGIN_FILE ), array(), VERSION );
		wp_enqueue_script(
			self::HANDLE,
			plugins_url( 'assets/js/login.js', PLUGIN_FILE ),
			$deps,
			VERSION,
			array(
				'in_footer' => true,
				'strategy'  => 'defer',
			)
		);

		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( (string) $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only, re-validated server side.

		wp_add_inline_script(
			self::HANDLE,
			'window.bloclabsSsi = ' . wp_json_encode(
				array(
					'restBase'    => esc_url_raw( $this->rest_base() ),
					'token'       => PageToken::create(),
					'tokenHeader' => BrowserController::TOKEN_HEADER,
					'redirectTo'  => $redirect,
					'schemes'     => PresentationOffer::wallet_schemes(),
					'i18n'        => array(
						'starting' => __( 'Preparing your request…', 'bloclabs-ssi-login' ),
						'waiting'  => __( 'Waiting for your wallet…', 'bloclabs-ssi-login' ),
						'verified' => __( 'Verified. Logging you in…', 'bloclabs-ssi-login' ),
						'failed'   => __( 'The credential was not accepted.', 'bloclabs-ssi-login' ),
						'expired'  => __( 'The request expired. Start again.', 'bloclabs-ssi-login' ),
						'error'    => __( 'Something went wrong. Please try again.', 'bloclabs-ssi-login' ),
					),
				)
			) . ';',
			'before'
		);
	}
}
