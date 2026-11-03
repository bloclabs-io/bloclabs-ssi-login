<?php
/**
 * Database and path settings for the WordPress test library.
 *
 * Credentials and the core path come from the environment so this file holds
 * no deployment-specific hosts. Defaults match the Integration (WordPress) CI
 * job, which publishes the MySQL service on the loopback address.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

$bloclabs_ssi_core = getenv( 'WP_CORE_DIR' );
if ( ! is_string( $bloclabs_ssi_core ) || '' === $bloclabs_ssi_core ) {
	$bloclabs_ssi_core = dirname( __DIR__ ) . '/vendor/wordpress';
}

define( 'ABSPATH', rtrim( $bloclabs_ssi_core, '/' ) . '/' );

define( 'WP_DEFAULT_THEME', 'twentytwentyfour' );
define( 'WP_DEBUG', true );

$bloclabs_ssi_db_name = getenv( 'WP_TESTS_DB_NAME' );
$bloclabs_ssi_db_user = getenv( 'WP_TESTS_DB_USER' );
$bloclabs_ssi_db_pass = getenv( 'WP_TESTS_DB_PASSWORD' );
$bloclabs_ssi_db_host = getenv( 'WP_TESTS_DB_HOST' );

define( 'DB_NAME', is_string( $bloclabs_ssi_db_name ) && '' !== $bloclabs_ssi_db_name ? $bloclabs_ssi_db_name : 'wordpress_test' );
define( 'DB_USER', is_string( $bloclabs_ssi_db_user ) && '' !== $bloclabs_ssi_db_user ? $bloclabs_ssi_db_user : 'root' );
define( 'DB_PASSWORD', is_string( $bloclabs_ssi_db_pass ) && '' !== $bloclabs_ssi_db_pass ? $bloclabs_ssi_db_pass : 'root' );
define( 'DB_HOST', is_string( $bloclabs_ssi_db_host ) && '' !== $bloclabs_ssi_db_host ? $bloclabs_ssi_db_host : '127.0.0.1' );
unset( $bloclabs_ssi_db_name, $bloclabs_ssi_db_user, $bloclabs_ssi_db_pass, $bloclabs_ssi_db_host );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

// Placeholders. The test library requires the constants; they are not secrets.
define( 'AUTH_KEY', 'put your unique phrase here' );
define( 'SECURE_AUTH_KEY', 'put your unique phrase here' );
define( 'LOGGED_IN_KEY', 'put your unique phrase here' );
define( 'NONCE_KEY', 'put your unique phrase here' );
define( 'AUTH_SALT', 'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT', 'put your unique phrase here' );
define( 'NONCE_SALT', 'put your unique phrase here' );

$table_prefix = 'wptests_'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- the WordPress test library requires this variable.

define( 'WP_TESTS_DOMAIN', 'example.org' );
define( 'WP_TESTS_EMAIL', 'admin@example.org' );
define( 'WP_TESTS_TITLE', 'Test Blog' );
define( 'WP_PHP_BINARY', PHP_BINARY );
define( 'WPLANG', '' );
