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
if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( string $url, int $component = -1 ) {
		return parse_url( $url, $component ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
	}
}
