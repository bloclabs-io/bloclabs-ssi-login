<?php
/**
 * The settings form inside WordPress.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Admin\SettingsPage;
use BlocLabs\SsiLogin\Plugin;

final class SettingsPageTest extends IntegrationTestCase {

	/**
	 * options.php unslashes the posted values before the sanitize callback runs;
	 * unslashing again ate backslashes typed into secrets, without notice (#29).
	 */
	public function test_backslashes_typed_into_a_secret_survive_the_save(): void {
		$page   = new SettingsPage( Plugin::instance()->settings() );
		$secret = 'top\\secret\\' . str_repeat( 'x', 32 );

		$out = $page->sanitize(
			array(
				'webhook_secret'   => $secret,
				'firefly_url'      => 'https://firefly.example',
				'default_role'     => 'subscriber',
				'client_ip_header' => 'HTTP_CF_CONNECTING_IP',
			)
		);

		$this->assertSame( $secret, $out['webhook_secret'] );
		$this->assertSame( 'subscriber', $out['default_role'] );
		$this->assertSame( 'HTTP_CF_CONNECTING_IP', $out['client_ip_header'] );
	}
}
