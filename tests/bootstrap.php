<?php
/**
 * Unit-test bootstrap: the pure classes only, with a handful of WordPress
 * functions stubbed. Integration tests against a real WordPress live in the
 * roadmap (wp-env).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

require dirname( __DIR__ ) . '/vendor/autoload.php';

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['bloclabs_ssi_test_options'] = array();

if ( ! function_exists( 'get_option' ) ) {
	function get_option( string $name, $default_value = false ) {
		return $GLOBALS['bloclabs_ssi_test_options'][ $name ] ?? $default_value;
	}
}
if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES );
	}
}
if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( string $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		return $value;
	}
}
if ( ! function_exists( 'wp_nonce_tick' ) ) {
	function wp_nonce_tick( $action = -1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		return $GLOBALS['bloclabs_ssi_test_tick'] ?? 1000;
	}
}
if ( ! function_exists( 'wp_hash' ) ) {
	function wp_hash( $data, $scheme = 'auth' ) {
		return hash_hmac( 'md5', (string) $data, 'test-salt-' . $scheme );
	}
}
if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( string $url, int $component = -1 ) {
		return parse_url( $url, $component ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
	}
}
if ( ! function_exists( 'is_multisite' ) ) {
	function is_multisite(): bool {
		return ! empty( $GLOBALS['bloclabs_ssi_test_multisite'] );
	}
}
if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter, WordPress.WP.I18n
		return $text;
	}
}

$GLOBALS['bloclabs_ssi_test_hooks'] = array();

if ( ! function_exists( 'add_action' ) ) {
	function add_action( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		$GLOBALS['bloclabs_ssi_test_hooks'][ $hook ] = $callback;
		return true;
	}
}
if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		$GLOBALS['bloclabs_ssi_test_hooks'][ $hook ] = $callback;
		return true;
	}
}
if ( ! function_exists( 'add_options_page' ) ) {
	function add_options_page( $page_title, $menu_title, $capability, $menu_slug, $callback = '', $position = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		$GLOBALS['bloclabs_ssi_test_options_page'] = array(
			'capability' => $capability,
			'menu_slug'  => $menu_slug,
		);
		return 'settings_page_' . $menu_slug;
	}
}
