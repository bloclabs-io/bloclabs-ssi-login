<?php
/**
 * Boots a real WordPress for the integration suite.
 *
 * The project autoloader also registers PHPUnit 10, which `composer test` uses.
 * This process is PHPUnit 9 (see bin/run-integration.sh). PHPUnit 10's classes
 * are taken out of that autoloader so a not-yet-loaded PHPUnit class cannot be
 * filled in from the other major version.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

$bloclabs_ssi_root = dirname( __DIR__, 2 );

require $bloclabs_ssi_root . '/vendor/autoload.php';
require __DIR__ . '/Support/CookieCapture.php';

// Composer resolves a package classmap through vendor/composer/../, so the
// marker is the phpunit package directory rather than vendor/phpunit.
$bloclabs_ssi_loaders = spl_autoload_functions();
if ( ! is_array( $bloclabs_ssi_loaders ) ) {
	$bloclabs_ssi_loaders = array();
}
foreach ( $bloclabs_ssi_loaders as $bloclabs_ssi_loader ) {
	if ( ! is_array( $bloclabs_ssi_loader ) || ! $bloclabs_ssi_loader[0] instanceof Composer\Autoload\ClassLoader ) {
		continue;
	}

	$bloclabs_ssi_map     = new ReflectionProperty( $bloclabs_ssi_loader[0], 'classMap' );
	$bloclabs_ssi_classes = $bloclabs_ssi_map->getValue( $bloclabs_ssi_loader[0] );
	$bloclabs_ssi_suite   = $bloclabs_ssi_classes['PHPUnit\\Framework\\TestSuite'] ?? '';
	if ( ! is_string( $bloclabs_ssi_suite ) || ! str_contains( $bloclabs_ssi_suite, 'phpunit' . DIRECTORY_SEPARATOR . 'phpunit' . DIRECTORY_SEPARATOR ) ) {
		continue;
	}
	if ( str_contains( $bloclabs_ssi_suite, DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR . 'phpunit9' . DIRECTORY_SEPARATOR ) ) {
		continue;
	}

	foreach ( $bloclabs_ssi_classes as $bloclabs_ssi_class => $bloclabs_ssi_file ) {
		$bloclabs_ssi_hidden = str_starts_with( $bloclabs_ssi_class, 'PHPUnit\\' )
			|| str_starts_with( $bloclabs_ssi_class, 'SebastianBergmann\\' )
			|| str_starts_with( $bloclabs_ssi_class, 'PharIo\\' )
			|| str_starts_with( $bloclabs_ssi_class, 'TheSeer\\' );
		if ( $bloclabs_ssi_hidden ) {
			unset( $bloclabs_ssi_classes[ $bloclabs_ssi_class ] );
		}
	}
	$bloclabs_ssi_map->setValue( $bloclabs_ssi_loader[0], $bloclabs_ssi_classes );

	// PHPUnit 9 registered its loader first. Keep it ahead of this one.
	spl_autoload_unregister( $bloclabs_ssi_loader );
	spl_autoload_register( $bloclabs_ssi_loader, true, false );
}
unset( $bloclabs_ssi_loaders, $bloclabs_ssi_loader, $bloclabs_ssi_map, $bloclabs_ssi_classes, $bloclabs_ssi_suite, $bloclabs_ssi_class, $bloclabs_ssi_file, $bloclabs_ssi_hidden );

$bloclabs_ssi_config = dirname( __DIR__ ) . '/wp-tests-config.php';
putenv( 'WP_PHPUNIT__TESTS_CONFIG=' . $bloclabs_ssi_config ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- the test library reads this with getenv().
$_ENV['WP_PHPUNIT__TESTS_CONFIG']    = $bloclabs_ssi_config;
$_SERVER['WP_PHPUNIT__TESTS_CONFIG'] = $bloclabs_ssi_config;

$bloclabs_ssi_tests_dir = getenv( 'WP_PHPUNIT__DIR' );
if ( ! is_string( $bloclabs_ssi_tests_dir ) || '' === $bloclabs_ssi_tests_dir ) {
	$bloclabs_ssi_tests_dir = $bloclabs_ssi_root . '/vendor/wp-phpunit/wp-phpunit';
}

define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', $bloclabs_ssi_root . '/vendor/yoast/phpunit-polyfills' );

require $bloclabs_ssi_tests_dir . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	static function () use ( $bloclabs_ssi_root ): void {
		// Optional real WooCommerce coverage; no dependency in the default suite.
		$woocommerce = getenv( 'WOOCOMMERCE_PLUGIN_FILE' );
		if ( is_string( $woocommerce ) && '' !== $woocommerce ) {
			require $woocommerce;
			add_action( 'init', array( 'WC_Install', 'create_tables' ), -10 );
		}

		require $bloclabs_ssi_root . '/bloclabs-ssi-login.php';

		// In place before the first rest_api_init, which is when the plugin caches the client.
		add_filter(
			'bloclabs_ssi_verifier_client',
			static fn () => BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake::instance()
		);
		BlocLabs\SsiLogin\Tests\Integration\Support\FireFlyHttpFake::instance()->register();
	}
);

/*
 * The library prints install progress. Buffer it so that output does not count
 * as headers already sent: BrowserBinding refuses to set the login cookie then,
 * which would make every /initiate call look unavailable.
 */
ob_start();
require $bloclabs_ssi_tests_dir . '/includes/bootstrap.php';
ob_end_clean();

/*
 * PHPUnit prints its banner with echo before the first test. Once anything has
 * been written, headers_sent() is true and BrowserBinding will not set the
 * login cookie. Hold that output until the process ends.
 */
ob_start();
register_shutdown_function(
	static function (): void {
		while ( ob_get_level() > 0 ) {
			ob_end_flush();
		}
	}
);
