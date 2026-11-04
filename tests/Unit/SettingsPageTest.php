<?php
/**
 * Regression tests for the settings page: capability (#27), numeric bounds (#26), the client IP header warning (#45).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Admin\SettingsPage;
use BlocLabs\SsiLogin\Config\Settings;
use PHPUnit\Framework\TestCase;

final class SettingsPageTest extends TestCase {

	private const SAVE_FILTER = 'option_page_capability_bloclabs-ssi-login';

	protected function setUp(): void {
		$GLOBALS['bloclabs_ssi_test_hooks']   = array();
		$GLOBALS['bloclabs_ssi_test_options'] = array();
		unset( $GLOBALS['bloclabs_ssi_test_options_page'] );
	}

	protected function tearDown(): void {
		$GLOBALS['bloclabs_ssi_test_options'] = array();
		unset( $GLOBALS['bloclabs_ssi_test_multisite'], $GLOBALS['bloclabs_ssi_test_options_page'] );
	}

	public function test_a_single_site_keeps_manage_options(): void {
		$GLOBALS['bloclabs_ssi_test_multisite'] = false;

		$this->assertSame( 'manage_options', SettingsPage::capability() );
	}

	public function test_multisite_needs_the_network_capability(): void {
		$GLOBALS['bloclabs_ssi_test_multisite'] = true;

		$this->assertSame( 'manage_network_options', SettingsPage::capability() );
	}

	public function test_the_menu_entry_uses_the_same_capability(): void {
		$GLOBALS['bloclabs_ssi_test_multisite'] = true;

		( new SettingsPage( new Settings() ) )->add_page();

		$this->assertSame( 'manage_network_options', $GLOBALS['bloclabs_ssi_test_options_page']['capability'] );
		$this->assertSame( 'bloclabs-ssi-login', $GLOBALS['bloclabs_ssi_test_options_page']['menu_slug'] );
	}

	/**
	 * options.php lets anyone with manage_options submit a whitelisted option
	 * page unless this filter raises the capability, so the save must be gated
	 * exactly like the page.
	 */
	public function test_the_save_is_gated_by_the_same_capability(): void {
		( new SettingsPage( new Settings() ) )->register();

		$this->assertArrayHasKey( self::SAVE_FILTER, $GLOBALS['bloclabs_ssi_test_hooks'] );
		$filter = $GLOBALS['bloclabs_ssi_test_hooks'][ self::SAVE_FILTER ];

		$GLOBALS['bloclabs_ssi_test_multisite'] = true;
		$this->assertSame( 'manage_network_options', $filter( 'manage_options' ) );

		$GLOBALS['bloclabs_ssi_test_multisite'] = false;
		$this->assertSame( 'manage_options', $filter( 'manage_options' ) );
	}

	/**
	 * A cap of 0 would refuse every login and 0 proxies would index past the
	 * header, so the form cannot save them; nor an unbounded lifetime or cap.
	 */
	public function test_the_numeric_settings_are_bounded(): void {
		$page = new SettingsPage( new Settings() );

		$low = $page->sanitize(
			array(
				'attempt_ttl'        => '5',
				'max_pending_per_ip' => '0',
				'max_pending_total'  => '0',
				'client_ip_proxies'  => '0',
			)
		);
		$this->assertSame( 60, $low['attempt_ttl'] );
		$this->assertSame( 1, $low['max_pending_per_ip'] );
		$this->assertSame( 10, $low['max_pending_total'] );
		$this->assertSame( 1, $low['client_ip_proxies'] );

		$high = $page->sanitize(
			array(
				'attempt_ttl'        => '99999',
				'max_pending_per_ip' => '99999',
				'max_pending_total'  => '9999999',
				'client_ip_proxies'  => '99',
			)
		);
		$this->assertSame( 600, $high['attempt_ttl'] );
		$this->assertSame( 1000, $high['max_pending_per_ip'] );
		$this->assertSame( 100000, $high['max_pending_total'] );
		$this->assertSame( 10, $high['client_ip_proxies'] );

		$kept = $page->sanitize(
			array(
				'max_pending_per_ip' => '25',
				'max_pending_total'  => '2000',
				'client_ip_proxies'  => '2',
				'client_ip_header'   => ' HTTP_X_FORWARDED_FOR ',
			)
		);
		$this->assertSame( 25, $kept['max_pending_per_ip'] );
		$this->assertSame( 2000, $kept['max_pending_total'] );
		$this->assertSame( 2, $kept['client_ip_proxies'] );
		$this->assertSame( 'HTTP_X_FORWARDED_FOR', $kept['client_ip_header'] );
	}

	/**
	 * Apache mod_remoteip (on in the official WordPress Docker image) resolves
	 * the client and removes the header before PHP runs, so an administrator's
	 * own request arrives without it: the page must say so.
	 */
	public function test_warns_when_the_configured_header_is_missing_from_the_request(): void {
		$page = $this->page( array( 'client_ip_header' => 'HTTP_X_FORWARDED_FOR' ) );

		$warning = $page->client_ip_header_warning( array( 'REMOTE_ADDR' => '198.51.100.7' ) );

		$this->assertIsString( $warning );
		$this->assertStringContainsString( 'HTTP_X_FORWARDED_FOR', $warning );
		$this->assertStringContainsString( 'mod_remoteip', $warning );
	}

	/**
	 * A proxy that sets the header on every request, even one with public
	 * addresses such as Cloudflare, is the configuration the setting is for.
	 */
	public function test_no_warning_when_the_header_arrives(): void {
		$page = $this->page( array( 'client_ip_header' => 'HTTP_CF_CONNECTING_IP' ) );

		$this->assertNull(
			$page->client_ip_header_warning(
				array(
					'REMOTE_ADDR'           => '198.51.100.7',
					'HTTP_CF_CONNECTING_IP' => '203.0.113.50',
				)
			)
		);
	}

	public function test_no_warning_without_a_configured_header(): void {
		$page = $this->page( array( 'client_ip_header' => '' ) );

		$this->assertNull( $page->client_ip_header_warning( array( 'REMOTE_ADDR' => '198.51.100.7' ) ) );
	}

	/**
	 * @param array<string, mixed> $values
	 */
	private function page( array $values ): SettingsPage {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = $values;
		return new SettingsPage( new Settings() );
	}
}
