<?php
/**
 * Who may list and unlink credentials, and what the CLI is willing to print.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Admin\UserLinksScreen;
use BlocLabs\SsiLogin\Cli\Command;
use BlocLabs\SsiLogin\Plugin;
use PHPUnit\Framework\TestCase;

final class UserLinksTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['bloclabs_ssi_test_multisite']   = false;
		$GLOBALS['bloclabs_ssi_test_super_admin'] = false;
		$GLOBALS['bloclabs_ssi_test_caps']        = array();
		\WP_CLI::$lines                           = array();
	}

	protected function tearDown(): void {
		unset( $GLOBALS['bloclabs_ssi_test_multisite'], $GLOBALS['bloclabs_ssi_test_super_admin'], $GLOBALS['bloclabs_ssi_test_caps'], $GLOBALS['bloclabs_ssi_test_cli_decline'] );
	}

	public function test_single_site_requires_edit_users(): void {
		$this->assertSame( 'edit_users', UserLinksScreen::required_capability() );
		$this->assertFalse( UserLinksScreen::can_manage() );

		$GLOBALS['bloclabs_ssi_test_caps'] = array( 'manage_network_users' );
		$this->assertFalse( UserLinksScreen::can_manage(), 'a network capability does not grant unlink on a single site' );

		$GLOBALS['bloclabs_ssi_test_caps'] = array( 'edit_users' );
		$this->assertTrue( UserLinksScreen::can_manage() );
	}

	public function test_multisite_requires_a_network_administrator(): void {
		$GLOBALS['bloclabs_ssi_test_multisite'] = true;
		$this->assertSame( 'manage_network_users', UserLinksScreen::required_capability() );

		$GLOBALS['bloclabs_ssi_test_caps'] = array( 'edit_users', 'manage_network_users' );
		$this->assertFalse( UserLinksScreen::can_manage(), 'the capability alone is not enough: the account must be a network administrator' );

		$GLOBALS['bloclabs_ssi_test_super_admin'] = true;
		$GLOBALS['bloclabs_ssi_test_caps']        = array( 'edit_users' );
		$this->assertFalse( UserLinksScreen::can_manage(), 'a network administrator still needs manage_network_users' );

		$GLOBALS['bloclabs_ssi_test_caps'] = array( 'manage_network_users' );
		$this->assertTrue( UserLinksScreen::can_manage() );
	}

	public function test_cli_refuses_without_the_capability_before_it_reads_links(): void {
		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'edit_users' );
		( new Command( Plugin::instance() ) )->links( array( 'list' ), array() );
	}

	public function test_cli_refuses_a_multisite_site_administrator(): void {
		$GLOBALS['bloclabs_ssi_test_multisite'] = true;
		$GLOBALS['bloclabs_ssi_test_caps']      = array( 'edit_users', 'manage_network_users' );

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'network administrator' );
		( new Command( Plugin::instance() ) )->links( array( 'unlink', 'ada' ), array() );
	}

	public function test_cli_rejects_an_unknown_subcommand_without_declaring_user(): void {
		$GLOBALS['bloclabs_ssi_test_caps'] = array( 'edit_users' );

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'Usage:' );
		( new Command( Plugin::instance() ) )->links( array(), array( 'user' => 'ada' ) );
	}

	public function test_a_listing_line_cannot_smuggle_a_subject_into_another_column(): void {
		$subject = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
		$line    = Command::format_link( 'ada', 'did:key #3f9a1c2e', "did:web:issuer.example\n{$subject}", '' );

		$this->assertSame( "ada\tdid:key #3f9a1c2e\tdid:web:issuer.example {$subject}\tnever", $line );
		$this->assertStringNotContainsString( "\n", $line );
		$this->assertStringNotContainsString( "\t" . $subject, $line );
		$this->assertCount( 4, explode( "\t", $line ) );
	}
}
