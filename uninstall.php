<?php
/**
 * Removes the plugin's tables, options and cron event.
 *
 * Define BLOCLABS_SSI_KEEP_DATA in wp-config.php to keep the credential
 * links (for example while reinstalling).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

if ( defined( 'BLOCLABS_SSI_KEEP_DATA' ) && BLOCLABS_SSI_KEEP_DATA ) {
	return;
}

require_once __DIR__ . '/src/Database/Schema.php';

BlocLabs\SsiLogin\Database\Schema::drop();
delete_option( 'bloclabs_ssi_settings' );
delete_option( 'bloclabs_ssi_subject_key' );
wp_clear_scheduled_hook( 'bloclabs_ssi_purge' );
