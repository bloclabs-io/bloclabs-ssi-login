<?php
/**
 * Activation and deactivation. Uninstall lives in uninstall.php.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Cron\PurgeExpired;
use BlocLabs\SsiLogin\Database\Schema;

final class Lifecycle {

	/**
	 * @param bool $network_wide True when network-activated on multisite.
	 */
	public static function activate( $network_wide = false ): void {
		// Each site needs its own tables, cron event and settings; network activation would set up one site only.
		if ( $network_wide && is_multisite() ) {
			wp_die(
				esc_html__( 'blocLabs SSI Login cannot be network-activated yet. Activate it on each site instead.', 'bloclabs-ssi-login' ),
				esc_html__( 'Plugin not activated', 'bloclabs-ssi-login' ),
				array( 'back_link' => true )
			);
		}

		Schema::install();
		Settings::ensure_option();
		wp_set_option_autoload( Settings::OPTION, false );
		Settings::ensure_subject_key();
		PurgeExpired::schedule();
	}

	public static function deactivate(): void {
		PurgeExpired::unschedule();
	}
}
