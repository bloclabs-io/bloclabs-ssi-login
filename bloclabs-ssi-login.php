<?php
/**
 * Plugin Name:       blocLabs SSI Login
 * Plugin URI:        https://github.com/bloclabs-io/bloclabs-ssi-login
 * Description:       Passwordless login with Verifiable Credentials (OpenID4VP). Every login decision is attested on chain and delivered to WordPress through Hyperledger FireFly event streams.
 * Version:           0.1.0-dev
 * Requires at least: 6.6
 * Requires PHP:      8.1
 * Author:            blocLabs
 * Author URI:        https://bloclabs.io
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bloclabs-ssi-login
 * Domain Path:       /languages
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin;

defined( 'ABSPATH' ) || exit;

const VERSION     = '0.1.0-dev';
const PLUGIN_FILE = __FILE__;
const PLUGIN_DIR  = __DIR__;

/*
 * Composer's autoloader when it exists (development, or a build that bundles
 * dependencies). The plugin has no runtime dependencies, so a PSR-4 fallback
 * keeps a plain checkout working without `composer install`.
 */
if ( is_readable( __DIR__ . '/vendor/autoload.php' ) ) {
	require_once __DIR__ . '/vendor/autoload.php';
} else {
	spl_autoload_register(
		static function ( string $class_name ): void {
			$prefix = __NAMESPACE__ . '\\';
			if ( ! str_starts_with( $class_name, $prefix ) ) {
				return;
			}
			$relative = str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) );
			$file     = __DIR__ . '/src/' . $relative . '.php';
			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}
	);
}

register_activation_hook( __FILE__, array( Lifecycle::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Lifecycle::class, 'deactivate' ) );

add_action( 'plugins_loaded', static fn () => Plugin::instance()->boot() );
