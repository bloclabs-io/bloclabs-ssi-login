<?php
/**
 * Demo home page. A signed-in wallet user is greeted by display name.
 *
 * This file lives under a subdirectory of mu-plugins. WordPress includes
 * every PHP file in the mu-plugins root on each request, so the template
 * must not sit there or it would be printed during bootstrap.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

defined( 'ABSPATH' ) || exit;

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php echo esc_attr( get_bloginfo( 'charset' ) ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<?php wp_head(); ?>
</head>
<body <?php body_class( 'bloclabs-demo' ); ?>>
<?php wp_body_open(); ?>
<main class="bloclabs-demo-page">
	<p class="bloclabs-demo-mark"><?php esc_html_e( 'blocLabs', 'bloclabs-ssi-login' ); ?></p>
	<h1><?php esc_html_e( 'Credential login', 'bloclabs-ssi-login' ); ?></h1>

	<section class="bloclabs-demo-card">
		<?php bloclabs_ssi_demo_greeting(); ?>
	</section>

	<section class="bloclabs-demo-card">
		<h2><?php esc_html_e( 'Wallet', 'bloclabs-ssi-login' ); ?></h2>
		<p><?php esc_html_e( 'Receive the demo credential here, then present it on the login page.', 'bloclabs-ssi-login' ); ?></p>
		<p><a class="bloclabs-demo-link" href="<?php echo esc_url( 'http://127.0.0.1:7106' ); ?>"><?php esc_html_e( 'Open the wallet', 'bloclabs-ssi-login' ); ?></a></p>
	</section>
</main>
<?php wp_footer(); ?>
</body>
</html>
