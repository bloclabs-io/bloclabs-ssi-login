<?php
/**
 * blocLabs look for the local demo: fonts, colours and the front page.
 *
 * The plugin itself stays unbranded. Only this demo mounts these files.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

defined( 'ABSPATH' ) || exit;

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once __DIR__ . '/bloclabs-demo/cli.php';
}

/**
 * Styles shared by the login screen and the demo front page.
 */
function bloclabs_ssi_demo_assets(): void {
	$css = __DIR__ . '/brand.css';

	wp_enqueue_style(
		'bloclabs-ssi-demo-fonts',
		'https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600&family=Exo:wght@600;700&display=swap',
		array(),
		'1'
	);
	wp_enqueue_style(
		'bloclabs-ssi-demo',
		content_url( 'mu-plugins/brand.css' ),
		array( 'bloclabs-ssi-demo-fonts' ),
		(string) filemtime( $css )
	);
}

add_action( 'wp_enqueue_scripts', 'bloclabs_ssi_demo_assets' );
add_action( 'login_enqueue_scripts', 'bloclabs_ssi_demo_assets' );

/**
 * The login header reads as blocLabs.
 */
function bloclabs_ssi_demo_login_header_text(): string {
	return 'blocLabs';
}

/**
 * The login header links back to the demo home page.
 */
function bloclabs_ssi_demo_login_header_url(): string {
	return home_url( '/' );
}

add_filter( 'login_headertext', 'bloclabs_ssi_demo_login_header_text' );
add_filter( 'login_headerurl', 'bloclabs_ssi_demo_login_header_url' );

/**
 * Browser title on the demo front page.
 *
 * @param string $title Title WordPress would have used.
 */
function bloclabs_ssi_demo_title( string $title ): string {
	if ( is_front_page() || is_home() ) {
		return 'blocLabs';
	}
	return $title;
}

add_filter( 'pre_get_document_title', 'bloclabs_ssi_demo_title' );

/**
 * Replaces the posts index with the demo home page.
 *
 * @param string $template Template WordPress selected.
 */
function bloclabs_ssi_demo_template( string $template ): string {
	if ( is_admin() || is_feed() || wp_doing_ajax() ) {
		return $template;
	}
	if ( is_front_page() || is_home() ) {
		return __DIR__ . '/bloclabs-demo/front-page.php';
	}
	return $template;
}

add_filter( 'template_include', 'bloclabs_ssi_demo_template' );

/**
 * Wallet page on this machine. The host port comes from the container
 * environment, which Compose sets from demo/.env. Anything else falls
 * back to the default, so a bad value cannot point the link elsewhere.
 */
function bloclabs_ssi_demo_wallet_url(): string {
	$configured = getenv( 'WALLET_WEB_PUBLIC_URL' );
	if ( is_string( $configured ) && 1 === preg_match( '#\Ahttp://127\.0\.0\.1:([0-9]{1,5})\z#', $configured, $match ) ) {
		$port = (int) $match[1];
		if ( $port >= 1 && $port <= 65535 ) {
			return $configured;
		}
	}
	return 'http://127.0.0.1:7106';
}

/**
 * Greeting on the demo home page.
 */
function bloclabs_ssi_demo_greeting(): void {
	if ( ! is_user_logged_in() ) {
		echo '<p>' . esc_html__( 'You are not signed in.', 'bloclabs-ssi-login' ) . '</p>';
		echo '<p><a class="bloclabs-demo-button" href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Log in', 'bloclabs-ssi-login' ) . '</a></p>';
		return;
	}

	$user = wp_get_current_user();
	$name = $user->display_name;
	if ( '' !== $name ) {
		echo '<p class="bloclabs-demo-hello">';
		echo esc_html(
			sprintf(
				/* translators: %s: the signed-in user's display name. */
				__( 'Signed in as %s', 'bloclabs-ssi-login' ),
				$name
			)
		);
		echo '</p>';
	} else {
		echo '<p class="bloclabs-demo-hello">' . esc_html__( 'Signed in', 'bloclabs-ssi-login' ) . '</p>';
	}
	echo '<p>' . esc_html__( 'This account was opened from the credential in your wallet.', 'bloclabs-ssi-login' ) . '</p>';
}
