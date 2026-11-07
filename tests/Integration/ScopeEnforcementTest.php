<?php
/**
 * A token request is confined to its scope (ADR 0007 §4 "Scope"; threat A4; #91):
 * every denied capability, for an ordinary account and for a multisite super administrator.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Auth\BearerAuthentication;
use BlocLabs\SsiLogin\Auth\ScopeEnforcement;
use BlocLabs\SsiLogin\Login\Scope;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Tests\Integration\Support\TokenLookupFake;

final class ScopeEnforcementTest extends IntegrationTestCase {

	private TokenLookupFake $tokens;

	protected function setUp(): void {
		parent::setUp();
		$this->tokens = new TokenLookupFake();
		( new BearerAuthentication( Plugin::instance()->settings(), $this->tokens, new ScopeEnforcement() ) )->register();
		$_SERVER['HTTPS'] = 'on';
		BearerAuthentication::reset();
	}

	protected function tearDown(): void {
		unset( $_SERVER['HTTPS'], $_SERVER['HTTP_AUTHORIZATION'] );
		BearerAuthentication::reset();
		parent::tearDown();
	}

	/**
	 * Authenticates the request with a token for the user, as WordPress runs it:
	 * the user determined at bootstrap, then the REST server's authentication check.
	 *
	 * @param list<string> $scope
	 */
	private function act_with_token( int $user_id, array $scope ): void {
		global $current_user;
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokens->mint( $user_id, $scope );
		$current_user                  = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- forces core to determine the user again.
		$this->assertSame( 0, wp_get_current_user()->ID, 'nobody until the REST boundary' );
		$this->assertTrue( rest_get_server()->check_authentication() );
		$this->assertSame( $user_id, get_current_user_id() );
		$this->assertNotNull( BearerAuthentication::current() );
	}

	private function act_with_session( int $user_id ): void {
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		BearerAuthentication::reset();
		wp_set_current_user( $user_id );
		$this->assertNull( BearerAuthentication::current() );
	}

	/**
	 * The self-service meta capabilities on the account itself, and every capability
	 * the denylist names: what A4 says a token must never reach.
	 *
	 * @return list<array{0: string, 1?: int}>
	 */
	private static function a4_checks( int $account ): array {
		$checks = array();
		foreach ( ScopeEnforcement::SELF_SERVICE as $capability ) {
			$checks[] = array( $capability, $account );
		}
		foreach ( Scope::DENIED as $capability ) {
			$checks[] = array( $capability );
		}
		foreach ( array( 'manage_network', 'manage_network_users', 'manage_network_options', 'manage_network_plugins', 'manage_network_themes', 'manage_sites' ) as $capability ) {
			$checks[] = array( $capability );
		}
		return $checks;
	}

	public function test_a_read_token_reads_and_nothing_else(): void {
		$editor = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->act_with_token( $editor, array( 'read' ) );

		$this->assertTrue( current_user_can( 'read' ) );
		$this->assertTrue( current_user_can( 'exist' ) ); // phpcs:ignore WordPress.WP.Capabilities.Unknown -- core grants it to every user after the filter.
		foreach ( array( 'edit_posts', 'publish_posts', 'upload_files', 'delete_posts', 'edit_others_posts', 'moderate_comments', 'manage_categories' ) as $capability ) {
			$this->assertFalse( current_user_can( $capability ), "{$capability} is the editor's, not the token's" );
		}
		$this->assertFalse( current_user_can( 'edit_user', $editor ), 'the account\'s own profile is off limits' );
		$this->assertFalse( current_user_can( 'create_app_password', $editor ) );
	}

	public function test_a_content_token_edits_content_within_what_the_account_may_do(): void {
		$author = self::factory()->user->create( array( 'role' => 'author' ) );
		$own    = self::factory()->post->create( array( 'post_author' => $author ) );
		$other  = self::factory()->post->create( array( 'post_author' => self::factory()->user->create( array( 'role' => 'author' ) ) ) );
		$this->act_with_token( $author, array( 'content' ) );

		$this->assertTrue( current_user_can( 'edit_posts' ) );
		$this->assertTrue( current_user_can( 'publish_posts' ) );
		$this->assertTrue( current_user_can( 'upload_files' ) );
		$this->assertTrue( current_user_can( 'edit_post', $own ), 'own post: edit_posts and edit_published_posts are in scope' );
		$this->assertFalse( current_user_can( 'edit_post', $other ), 'another author\'s post needs edit_others_posts, which an author lacks' );
		$this->assertFalse( current_user_can( 'edit_others_posts' ), 'a scope never grants what the account lacks' );
		$this->assertFalse( current_user_can( 'moderate_comments' ), 'in the account, not in the scope' );
		$this->assertFalse( current_user_can( 'edit_user', $author ) );
	}

	public function test_an_administrators_token_cannot_reach_any_a4_capability(): void {
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->act_with_session( $admin );
		$this->assertTrue( current_user_can( 'manage_options' ), 'as a session, the administrator is one' );
		$this->assertTrue( current_user_can( 'edit_user', $admin ) );
		$this->assertTrue( current_user_can( 'create_app_password', $admin ) );

		$this->act_with_token( $admin, array( 'content', 'read' ) );

		$this->assertTrue( current_user_can( 'edit_posts' ) );
		$this->assertTrue( current_user_can( 'edit_others_posts' ) === false, 'outside the scope even for an administrator' );
		foreach ( self::a4_checks( $admin ) as $check ) {
			$this->assertFalse( current_user_can( ...$check ), $check[0] . ' must be denied to a token' );
			$this->assertFalse( user_can( $admin, ...$check ), $check[0] . ' through user_can() too' );
		}
		$this->assertFalse( current_user_can( 'edit_user', self::factory()->user->create() ), 'other users\' profiles too' );
		$this->assertFalse( current_user_can( 'delete_user', $admin ) );
		$this->assertFalse( current_user_can( 'list_users' ) );
		$this->assertFalse( current_user_can( 'remove_users' ) );
	}

	public function test_a_multisite_super_administrator_is_confined_by_map_meta_cap(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Super administrators exist on multisite only.' );
		}
		$super = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $super );
		$this->act_with_session( $super );
		$this->assertTrue( is_super_admin( $super ) );
		$this->assertTrue( current_user_can( 'manage_network' ), 'as a session, everything' );
		$this->assertTrue( current_user_can( 'edit_user', $super ) );

		$this->act_with_token( $super, array( 'content' ) );

		$this->assertTrue( current_user_can( 'edit_posts' ) );
		$this->assertTrue( current_user_can( 'upload_files' ) );
		$this->assertFalse( current_user_can( 'edit_others_posts' ), 'has_cap() would grant a super administrator anything not explicitly denied' );
		$this->assertFalse( current_user_can( 'delete_others_posts' ) );
		foreach ( self::a4_checks( $super ) as $check ) {
			$this->assertFalse( current_user_can( ...$check ), $check[0] . ' must be denied to a super administrator\'s token' );
			$this->assertFalse( user_can( $super, ...$check ) );
		}
		$this->assertFalse( current_user_can( 'edit_user', self::factory()->user->create() ) );
		$this->assertFalse( current_user_can( 'manage_sites' ) );
		$this->assertFalse( current_user_can( 'create_sites' ) );
	}

	public function test_a_site_scope_cannot_smuggle_a_denied_capability(): void {
		add_filter(
			Scope::FILTER,
			static fn ( array $scopes ) => $scopes + array( 'ops' => array( 'read', 'manage_options', 'edit_users', 'manage_network_options', 'install_plugins' ) )
		);
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->act_with_token( $admin, array( 'ops' ) );

		$this->assertTrue( current_user_can( 'read' ) );
		foreach ( array( 'manage_options', 'edit_users', 'manage_network_options', 'install_plugins' ) as $capability ) {
			$this->assertFalse( current_user_can( $capability ), "{$capability} is denied whatever a scope says" );
		}
	}

	public function test_enforcement_only_touches_the_tokens_own_user(): void {
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$agent = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->act_with_token( $agent, array( 'read' ) );

		$this->assertTrue( user_can( $admin, 'manage_options' ), 'another user\'s capabilities are not narrowed' );
		$this->assertTrue( user_can( $admin, 'edit_user', $admin ) );
		$this->assertFalse( user_can( $agent, 'edit_user', $agent ) );
		$this->assertFalse( user_can( $agent, 'edit_posts' ) );
	}

	public function test_without_a_token_nothing_changes(): void {
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->act_with_session( $admin );

		$this->assertTrue( current_user_can( 'manage_options' ) );
		$this->assertTrue( current_user_can( 'edit_user', $admin ) );
		$this->assertTrue( current_user_can( 'create_app_password', $admin ) );
		$this->assertContains( 'administrator', wp_get_current_user()->roles );
	}

	public function test_a_demoted_account_demotes_its_token(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->act_with_token( $user_id, array( 'content' ) );
		$this->assertTrue( current_user_can( 'edit_posts' ) );

		( new \WP_User( $user_id ) )->set_role( 'subscriber' );
		BearerAuthentication::reset();
		$this->act_with_token( $user_id, array( 'content' ) );

		$this->assertTrue( current_user_can( 'read' ) );
		$this->assertFalse( current_user_can( 'edit_posts' ), 'capabilities are read from the account on every request' );
		$this->assertFalse( current_user_can( 'upload_files' ) );
	}
}
