<?php
/**
 * Scope names, the denylist and the intersection rule of ADR 0007 (#90).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Login\Scope;
use PHPUnit\Framework\TestCase;

final class ScopeTest extends TestCase {

	protected function tearDown(): void {
		$GLOBALS['bloclabs_ssi_test_options'] = array();
	}

	public function test_the_built_in_scopes_are_read_and_content(): void {
		$catalogue = Scope::catalogue();

		$this->assertSame( array( 'read', 'content' ), array_keys( $catalogue ) );
		$this->assertSame( array( 'read' ), $catalogue['read'] );
		$this->assertSame( array( 'read', 'edit_posts', 'edit_published_posts', 'publish_posts', 'delete_posts', 'upload_files' ), $catalogue['content'] );
	}

	public function test_no_built_in_capability_is_denied(): void {
		foreach ( Scope::built_in() as $name => $capabilities ) {
			foreach ( $capabilities as $capability ) {
				$this->assertFalse( Scope::is_denied( $capability ), "{$name} carries {$capability}" );
			}
		}
	}

	/**
	 * @return list<array{0: string}>
	 */
	public static function denied_capabilities(): array {
		$cases = array();
		foreach ( Scope::DENIED as $capability ) {
			$cases[] = array( $capability );
		}
		$cases[] = array( 'manage_network' );
		$cases[] = array( 'manage_network_options' );
		$cases[] = array( 'manage_network_users' );
		$cases[] = array( 'manage_network_plugins' );
		$cases[] = array( 'MANAGE_OPTIONS' );
		return $cases;
	}

	/**
	 * @dataProvider denied_capabilities
	 */
	public function test_the_denylist_bars_administrative_capabilities( string $capability ): void {
		$this->assertTrue( Scope::is_denied( $capability ) );
	}

	public function test_the_denylist_covers_what_safe_role_refuses(): void {
		foreach ( array( 'manage_options', 'edit_users', 'promote_users' ) as $capability ) {
			$this->assertContains( $capability, Scope::DENIED );
		}
	}

	public function test_a_sites_filter_result_is_normalised_and_denied_capabilities_dropped(): void {
		$normalised = Scope::normalise(
			array(
				'read'       => array( 'read' ),
				'moderation' => array( 'read', 'moderate_comments', 'edit_users', 'manage_network_options', 'moderate_comments', '', 7 ),
				'Bad Name'   => array( 'read' ),
				7            => array( 'read' ),
				'noscope'    => 'read',
				'admin'      => array( 'manage_options', 'update_core', 'install_plugins' ),
			)
		);

		$this->assertSame( array( 'read', 'moderation', 'admin' ), array_keys( $normalised ) );
		$this->assertSame( array( 'read', 'moderate_comments' ), $normalised['moderation'], 'denied, empty, duplicate and non-string capabilities go' );
		$this->assertSame( array(), $normalised['admin'], 'a scope made only of denied capabilities grants nothing' );
		$this->assertSame( array(), Scope::normalise( 'read' ), 'a filter that returns no array leaves no scopes' );
	}

	public function test_names_accepts_a_list_or_a_separated_string_and_keeps_well_formed_names_once(): void {
		$this->assertSame( array( 'read', 'content' ), Scope::names( array( 'read', 'content', 'read' ) ) );
		$this->assertSame( array( 'read', 'content' ), Scope::names( 'read, content read' ) );
		$this->assertSame( array( 'read' ), Scope::names( array( 'read', 'Read', '', ' content', 'a-b_c!', 42, null ) ) );
		$this->assertSame( array(), Scope::names( null ) );
		$this->assertSame( array(), Scope::names( 7 ) );
		$this->assertSame( array(), Scope::names( str_repeat( 'a', 33 ) ), 'at most 32 characters' );
	}

	public function test_the_site_setting_only_names_scopes_the_site_knows(): void {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array( 'agent_scopes' => 'content, unknown ,read' );

		$this->assertSame( array( 'content', 'read' ), Scope::site( new Settings() ) );

		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array( 'agent_scopes' => '' );
		$this->assertSame( array(), Scope::site( new Settings() ), 'an empty setting allows no agent scope at all' );

		$GLOBALS['bloclabs_ssi_test_options'] = array();
		$this->assertSame( array( 'read', 'content' ), Scope::site( new Settings() ), 'the default allows both built-in scopes' );
	}

	public function test_a_grant_is_the_intersection_and_can_only_narrow(): void {
		$site = array( 'read', 'content' );

		$this->assertSame( array( 'content', 'read' ), Scope::grant( array( 'content', 'read' ), null, $site ), 'no credential limit: requested ∩ site, in the order requested' );
		$this->assertSame( array( 'read' ), Scope::grant( array( 'content', 'read' ), array( 'read' ), $site ), 'the credential narrows' );
		$this->assertSame( array( 'read' ), Scope::grant( array( 'content', 'read' ), null, array( 'read' ) ), 'the site narrows' );
		$this->assertSame( array( 'read' ), Scope::grant( array( 'read', 'admin' ), array( 'read', 'admin' ), $site ), 'a scope the site does not allow is never granted, whoever asks for it' );
		$this->assertSame( array(), Scope::grant( array( 'content' ), array( 'read' ), $site ), 'nothing in common: refuse' );
		$this->assertSame( array(), Scope::grant( array( 'content' ), array(), $site ), 'a credential that allows nothing allows nothing' );
		$this->assertSame( array(), Scope::grant( array(), null, $site ), 'nothing requested: refuse' );
	}

	public function test_capabilities_are_the_union_of_the_granted_scopes(): void {
		$this->assertSame( array( 'read' ), Scope::capabilities( array( 'read' ) ) );
		$this->assertSame( array( 'read', 'edit_posts', 'edit_published_posts', 'publish_posts', 'delete_posts', 'upload_files' ), Scope::capabilities( array( 'read', 'content' ) ) );
		$this->assertSame( array(), Scope::capabilities( array( 'unknown' ) ) );
		$this->assertSame( array(), Scope::capabilities( array() ) );
	}
}
