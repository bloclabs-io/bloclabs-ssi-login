<?php
/**
 * Adds the "Log in with a digital credential" block to wp-login.php.
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
	}

	public function render(): void {
		$template = (string) apply_filters( 'bloclabs_ssi_login_template', PLUGIN_DIR . '/templates/login-block.php' );
		if ( is_readable( $template ) ) {
			include $template;
		}
	}
}
