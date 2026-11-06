<?php
/**
 * Adds the "Log in with a digital credential" block to WordPress and WooCommerce login forms.
 *
 * The password form stays. The block is plain markup; assets/js/login.js
 * drives it, and without JavaScript the block stays hidden.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\Assets\AssetManager;
use BlocLabs\SsiLogin\Config\Settings;

use const BlocLabs\SsiLogin\PLUGIN_DIR;

final class LoginScreen {

	public function __construct(
		private readonly Settings $settings,
		private readonly AssetManager $assets,
	) {}

	public function register(): void {
		add_action( 'login_enqueue_scripts', array( $this->assets, 'enqueue_login' ) );
		// `login_form` fires inside the form, on the log-in action only (not lost password or register).
		add_action( 'login_form', array( $this, 'render' ) );
		add_action( 'woocommerce_login_form', array( $this, 'render_woocommerce' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_woocommerce' ) );
	}

	/** Woo conditional tags are available only after the main query. */
	public function enqueue_woocommerce(): void {
		if ( ! $this->settings->enabled() || is_user_logged_in() || ! function_exists( 'is_account_page' ) || ! function_exists( 'is_checkout' ) ) {
			return;
		}
		if ( is_account_page() || is_checkout() ) {
			// Use the queried Woo page, never a request-supplied redirect or Host header.
			$redirect = wp_validate_redirect( (string) get_permalink(), home_url( '/' ) );
			$this->assets->enqueue_login( $redirect, true );
		}
	}

	public function render_woocommerce(): void {
		if ( $this->settings->enabled() && function_exists( 'WC' ) && ! is_user_logged_in() ) {
			$this->render();
		}
	}

	public function render(): void {
		$template = (string) apply_filters( 'bloclabs_ssi_login_template', PLUGIN_DIR . '/templates/login-block.php' );
		if ( is_readable( $template ) ) {
			include $template;
		}
	}
}
