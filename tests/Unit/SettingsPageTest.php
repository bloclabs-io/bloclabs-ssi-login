<?php
/**
 * Regression tests for the settings page capability (#27).
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
		$GLOBALS['bloclabs_ssi_test_hooks'] = array();
		unset( $GLOBALS['bloclabs_ssi_test_options_page'] );
	}

	protected function tearDown(): void {
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
}
