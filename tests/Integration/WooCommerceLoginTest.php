<?php
/**
 * The same login UI and REST flow on real WooCommerce pages, and without Woo.
 *
 * Set WOOCOMMERCE_PLUGIN_FILE to a downloaded woocommerce.php to run both modes.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Assets\AssetManager;
use BlocLabs\SsiLogin\Login\LoginScreen;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Rest\PageToken;

final class WooCommerceLoginTest extends IntegrationTestCase {

	private LoginScreen $screen;

	protected function setUp(): void {
		parent::setUp();
		$this->screen = new LoginScreen( Plugin::instance()->settings(), new AssetManager( Plugin::instance()->settings() ) );
		$this->screen->register();
		wp_dequeue_script( AssetManager::HANDLE );
		wp_dequeue_style( AssetManager::HANDLE );
		wp_scripts()->remove( AssetManager::HANDLE );
		wp_styles()->remove( AssetManager::HANDLE );
	}

	public function test_without_woocommerce_nothing_renders_or_loads(): void {
		if ( function_exists( 'WC' ) ) {
			$this->markTestSkipped( 'Run the default suite without WOOCOMMERCE_PLUGIN_FILE for absent coverage.' );
		}
		ob_start();
		do_action( 'woocommerce_login_form' );
		$this->assertSame( '', ob_get_clean() );
		$this->screen->enqueue_woocommerce();
		$this->assertFalse( wp_script_is( AssetManager::HANDLE, 'enqueued' ) );
	}

	/** @dataProvider woo_pages */
	public function test_woo_login_returns_to_its_page( string $page ): void {
		if ( ! function_exists( 'WC' ) ) {
			$this->markTestSkipped( 'Set WOOCOMMERCE_PLUGIN_FILE to test real WooCommerce.' );
		}
		$id = self::factory()->post->create(
			array(
				'post_type'   => 'page',
				'post_status' => 'publish',
				'post_name'   => $page,
			)
		);
		update_option( 'woocommerce_' . $page . '_page_id', $id );
		$this->go_to( get_permalink( $id ) );
		$_REQUEST['redirect_to'] = 'https://attacker.example/';
		$this->screen->enqueue_woocommerce();
		unset( $_REQUEST['redirect_to'] );
		$this->assertTrue( wp_script_is( AssetManager::HANDLE, 'enqueued' ) );
		$this->assertTrue( wp_style_is( AssetManager::HANDLE, 'enqueued' ) );
		$inline = implode( '', wp_scripts()->get_data( AssetManager::HANDLE, 'before' ) );
		$this->assertSame( 1, preg_match( '/window.bloclabsSsi = (.*);/', $inline, $match ) );
		$config = json_decode( $match[1], true );
		$this->assertSame( get_permalink( $id ), $config['redirectTo'] );
		$this->assertSame( PageToken::create(), $config['token'] );

		ob_start();
		woocommerce_login_form();
		$html = ob_get_clean();
		$this->assertSame( 1, substr_count( $html, 'id="bloclabs-ssi"' ) );
		$this->assertStringContainsString( 'type="button"', $html );

		$user = self::factory()->user->create();
		$this->link_subject( $user );
		$response = $this->dispatch( 'POST', '/initiate', array( 'redirect_to' => $config['redirectTo'] ) );
		$this->assert_http( 201, $response );
		$attempt = $response->get_data()['attempt'];
		$row     = $this->attempt_row( $attempt );
		$this->attest( $row );
		$this->assert_http( 200, $this->dispatch( 'GET', '/status/' . $attempt ) );
		$complete = $this->complete( $attempt );
		$this->assert_http( 200, $complete );
		$this->assertSame( get_permalink( $id ), $complete->get_data()['redirect_to'] );
		$this->assertSame( array( $user ), $this->auth_cookie_users() );
	}

	public static function woo_pages(): array {
		return array(
			'My Account' => array( 'myaccount' ),
			'checkout'   => array( 'checkout' ),
		);
	}

	public function test_disabled_plugin_and_unrelated_pages_have_no_woo_ui_assets(): void {
		$this->configure( array( 'enabled' => false ) );
		ob_start();
		do_action( 'woocommerce_login_form' );
		$this->assertSame( '', ob_get_clean() );
		$this->screen->enqueue_woocommerce();
		$this->assertFalse( wp_script_is( AssetManager::HANDLE, 'enqueued' ) );
		$this->configure();
		$this->go_to( home_url( '/' ) );
		$this->screen->enqueue_woocommerce();
		$this->assertFalse( wp_script_is( AssetManager::HANDLE, 'enqueued' ) );
	}

	public function test_frontend_rest_stays_on_home_origin_and_wp_login_is_unchanged(): void {
		update_option( 'home', 'http://shop.example' );
		update_option( 'siteurl', 'http://wordpress.example/wp' );
		$assets = new AssetManager( Plugin::instance()->settings() );
		$this->assertStringStartsWith( 'http://shop.example/', $assets->rest_base( true ) );
		$this->assertStringStartsWith( 'http://wordpress.example/', $assets->rest_base() );
		$_REQUEST['redirect_to'] = '/existing-target/';
		$assets->enqueue_login();
		unset( $_REQUEST['redirect_to'] );
		$this->assertStringContainsString( 'existing-target', implode( '', wp_scripts()->get_data( AssetManager::HANDLE, 'before' ) ) );
	}
}
