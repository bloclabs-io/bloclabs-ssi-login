<?php
/**
 * Administrator unlink on the Users screens, and wp bloclabs-ssi links.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Admin\UserLinksScreen;
use BlocLabs\SsiLogin\Cli\Command;
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent;

final class UserLinksTest extends IntegrationTestCase {

	private const OTHER_SUBJECT = 'did:example:subject-should-stay-hidden';

	private const OTHER_ISSUER = 'did:web:second.example';

	private UserLinksScreen $screen;

	protected function setUp(): void {
		parent::setUp();
		$this->screen = new UserLinksScreen( Plugin::instance()->identities() );
		unset( $GLOBALS['bloclabs_ssi_test_cli_decline'] );
	}

	protected function tearDown(): void {
		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();
		unset( $_SERVER['REQUEST_METHOD'], $_SERVER['HTTP_REFERER'], $GLOBALS['bloclabs_ssi_test_cli_decline'] );
		parent::tearDown();
	}

	public function test_hooks_cover_the_users_screens_and_not_the_profile_screen(): void {
		$this->screen->register();

		$this->assertSame( 10, has_action( 'edit_user_profile', array( $this->screen, 'render_profile_section' ) ) );
		$this->assertFalse( has_action( 'show_user_profile', array( $this->screen, 'render_profile_section' ) ) );
		$this->assertSame( 10, has_filter( 'manage_users_columns', array( $this->screen, 'add_column' ) ) );
		$this->assertSame( 10, has_filter( 'wpmu_users_columns', array( $this->screen, 'add_column' ) ) );
		$this->assertSame( 10, has_action( 'admin_post_' . UserLinksScreen::ACTION, array( $this->screen, 'handle_unlink' ) ) );
	}

	public function test_an_administrator_sees_issuer_and_last_used_without_the_subject(): void {
		$user_id = self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_login' => 'ada',
			)
		);
		$this->link_subject( $user_id );
		$this->link_other( $user_id );
		$this->stamp_last_used( $this->subject_hash(), '2026-11-01 15:04:05' );

		$rows = Plugin::instance()->identities()->links_for( $user_id );
		$this->assertCount( 2, $rows );
		$this->assertArrayNotHasKey( 'subject_hash', $rows[0] );
		$this->assertSame( 'did:web:issuer.example', $rows[0]['issuer'] );

		wp_set_current_user( $this->manager() );
		$html = $this->screen->render_column( '', UserLinksScreen::COLUMN, $user_id );
		$this->assertStringContainsString( 'did:web:issuer.example', $html );
		$this->assertStringContainsString( self::OTHER_ISSUER, $html );
		$this->assertStringContainsString( 'Last used:', $html );
		$this->assertStringContainsString( '2026', $html );
		$this->assertStringContainsString( 'Never', $html );
		$this->assertStringContainsString( 'Unlink', $html );
		$this->assertStringContainsString( 'class="button button-small"', $html );
		$this->assertStringContainsString( 'credentials for ada', $html );
		$this->assertStringContainsString( 'None', $this->screen->render_column( '', UserLinksScreen::COLUMN, (string) self::factory()->user->create() ) );
		$this->assert_hides_subject( $html );

		ob_start();
		$this->screen->render_profile_section( get_userdata( $user_id ) );
		$profile = (string) ob_get_clean();
		$this->assertStringContainsString( '<h2 id="bloclabs-ssi-linked-credentials">', $profile );
		$this->assertStringContainsString( 'form-table', $profile );
		$this->assertStringContainsString( 'did:web:issuer.example', $profile );
		$this->assert_hides_subject( $profile );

		ob_start();
		$this->screen->render_unlink_forms();
		$forms = (string) ob_get_clean();
		$this->assertStringContainsString( 'method="post"', $forms );
		$this->assertStringContainsString( 'admin-post.php', $forms );
		$this->assertStringContainsString( 'name="' . UserLinksScreen::nonce_name( get_current_blog_id(), $user_id ) . '"', $forms );
		$this->assertStringNotContainsString( '<form', $html );
		$this->assert_hides_subject( $forms );
	}

	public function test_someone_who_cannot_edit_users_sees_nothing_and_cannot_unlink(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $subscriber );

		$columns = $this->screen->add_column( array( 'username' => 'Username' ) );
		$this->assertArrayNotHasKey( UserLinksScreen::COLUMN, $columns );
		$this->assertSame( '', $this->screen->render_column( '', UserLinksScreen::COLUMN, $user_id ) );

		ob_start();
		$this->screen->render_profile_section( get_userdata( $user_id ) );
		$this->assertSame( '', (string) ob_get_clean() );

		$this->post_unlink( $user_id, get_current_blog_id() );
		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			403
		);
		$this->assertSame( $user_id, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	public function test_unlink_removes_every_credential_for_that_account_only(): void {
		$ada = self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_login' => 'ada',
			)
		);
		$bea = self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_login' => 'bea',
			)
		);
		$this->link_subject( $ada );
		$this->link_other( $ada );
		$this->link_subject( $bea, 'did:example:bea-stays-linked' );

		wp_set_current_user( $this->manager() );
		$this->post_unlink( $ada, get_current_blog_id(), admin_url( 'user-edit.php?user_id=' . $ada ) );
		$url = $this->screen->unlink_request();

		$this->assertStringContainsString( 'bloclabs_ssi_unlinked=1', $url );
		$this->assertStringContainsString( 'user-edit.php', $url );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
		$this->assertSame( array(), Plugin::instance()->identities()->links_for( $ada ) );
		$this->assertSame( $bea, Plugin::instance()->identities()->user_id_for( $this->subject_hash( 'did:example:bea-stays-linked' ) ) );

		ob_start();
		$_GET['bloclabs_ssi_unlinked'] = '1';
		$this->screen->render_notice();
		$notice = (string) ob_get_clean();
		$this->assertStringContainsString( 'notice-success', $notice );
		$this->assertStringContainsString( 'Credential link removed.', $notice );
	}

	public function test_unlink_rejects_get_and_a_bad_nonce_and_will_not_redirect_off_site(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		wp_set_current_user( $this->manager() );

		$_SERVER['REQUEST_METHOD'] = 'GET';
		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			405
		);
		$this->assertNotNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );

		$this->post_unlink( $user_id, get_current_blog_id() );
		$_REQUEST[ UserLinksScreen::nonce_name( get_current_blog_id(), $user_id ) ] = 'not-a-nonce';
		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			403
		);
		$this->assertNotNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );

		$this->post_unlink( $user_id, get_current_blog_id(), 'https://evil.example/phish' );
		$url = $this->screen->unlink_request();
		$this->assertStringNotContainsString( 'evil.example', $url );
		$this->assertStringStartsWith( admin_url( 'users.php' ), $url );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	public function test_a_nonce_for_one_account_does_not_unlink_another(): void {
		$ada = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$bea = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $ada );
		$this->link_subject( $bea, 'did:example:bea-stays-linked' );
		wp_set_current_user( $this->manager() );

		$blog = get_current_blog_id();
		$this->post_unlink( $bea, $blog );
		$_REQUEST[ UserLinksScreen::nonce_name( $blog, $bea ) ] = wp_create_nonce( UserLinksScreen::nonce_action( $blog, $ada ) );

		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			403
		);
		$this->assertSame( $ada, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
		$this->assertSame( $bea, Plugin::instance()->identities()->user_id_for( $this->subject_hash( 'did:example:bea-stays-linked' ) ) );
	}

	public function test_an_unknown_site_is_refused(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		wp_set_current_user( $this->manager() );
		$this->post_unlink( $user_id, 987654 );

		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			400
		);
		$this->assertSame( $user_id, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	public function test_a_posted_array_is_not_an_account_id(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		wp_set_current_user( $this->manager() );
		$this->post_unlink( $user_id, get_current_blog_id() );
		$_POST['user_id']    = array( (string) $user_id );
		$_REQUEST['user_id'] = $_POST['user_id']; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the handler under test checks the nonce; this is the forged body.

		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			400
		);
		$this->assertSame( $user_id, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	public function test_cli_lists_and_unlinks_without_printing_the_subject(): void {
		$ada = self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_login' => 'ada',
				'user_email' => 'ada@example.com',
			)
		);
		$bea = self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_login' => 'bea',
			)
		);
		$this->link_subject( $ada );
		$this->link_other( $ada );
		$this->link_subject( $bea, 'did:example:bea-stays-linked' );
		$this->stamp_last_used( $this->subject_hash(), '2026-11-01 15:04:05' );

		wp_set_current_user( $this->manager() );
		$cli = $this->cli();
		$cli->links( array( 'list' ), array( 'user' => 'ada' ) );
		$all = implode( "\n", \WP_CLI::$lines );
		$this->assertStringContainsString( "account\tcredential\tissuer\tlast_used", $all );
		$this->assertStringContainsString( "ada\t", $all );
		$this->assertStringContainsString( 'did:web:issuer.example', $all );
		$this->assertStringContainsString( self::OTHER_ISSUER, $all );
		$this->assertStringContainsString( '2026-11-01 15:04:05', $all );
		$this->assertStringContainsString( "bea\t", $all );
		$this->assertStringNotContainsString( 'did:example:bea-stays-linked', $all );
		$this->assert_hides_subject( $all );
		$this->assertDoesNotMatchRegularExpression( '/\b[0-9a-f]{64}\b/', $all );

		\WP_CLI::$lines = array();
		$cli->links( array( 'list' ), array( 'login' => 'ada@example.com' ) );
		$one = implode( "\n", \WP_CLI::$lines );
		$this->assertStringContainsString( "ada\t", $one );
		$this->assertStringNotContainsString( "bea\t", $one );
		$this->assertStringNotContainsString( 'did:example:bea-stays-linked', $one );
		$this->assert_hides_subject( $one );

		\WP_CLI::$lines = array();
		$cli->links( array( 'list', (string) $bea ), array() );
		$by_id = implode( "\n", \WP_CLI::$lines );
		$this->assertStringContainsString( "bea\t", $by_id );
		$this->assertStringNotContainsString( "ada\t", $by_id );
		$this->assertStringNotContainsString( self::OTHER_ISSUER, $by_id );
		$this->assertStringNotContainsString( 'did:example:bea-stays-linked', $by_id );

		$subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $subscriber );
		try {
			$cli->links( array( 'unlink', 'ada' ), array( 'yes' => true ) );
			$this->fail( 'A subscriber must not unlink from WP-CLI.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( is_multisite() ? 'network administrator' : 'edit_users', $e->getMessage() );
		}
		$this->assertSame( $ada, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );

		wp_set_current_user( $this->manager() );
		$GLOBALS['bloclabs_ssi_test_cli_decline'] = true;
		try {
			$cli->links( array( 'unlink', 'ada' ), array() );
			$this->fail( 'Declining the confirmation must keep the link.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'aborted', $e->getMessage() );
		}
		$this->assertSame( $ada, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );

		unset( $GLOBALS['bloclabs_ssi_test_cli_decline'] );
		\WP_CLI::$lines = array();
		$cli->links( array( 'unlink', 'ada' ), array( 'yes' => true ) );
		$done = implode( "\n", \WP_CLI::$lines );
		$this->assertStringContainsString( 'Unlinked 2 credentials from ada.', $done );
		$this->assert_hides_subject( $done );
		$this->assertSame( array(), Plugin::instance()->identities()->links_for( $ada ) );
		$this->assertSame( $bea, Plugin::instance()->identities()->user_id_for( $this->subject_hash( 'did:example:bea-stays-linked' ) ) );
	}

	public function test_on_multisite_a_site_administrator_cannot_unlink_and_another_site_can(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'The network-administrator rule is enforced against a real multisite in that job.' );
		}

		$holder   = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$settings = Plugin::instance()->settings();
		$this->link_subject( $holder );
		$other      = self::factory()->blog->create();
		$other_hash = hash_hmac( 'sha256', self::OTHER_SUBJECT, $settings->subject_key() );
		add_user_to_blog( $other, $holder, 'subscriber' );
		// A new site has no plugin tables until the plugin is activated there.
		switch_to_blog( $other );
		$this->use_real_tables();
		Schema::install();
		$this->assertTrue(
			Plugin::instance()->identities()->link(
				$other_hash,
				$holder,
				IdentityRepository::label( self::OTHER_SUBJECT, $settings->subject_key() ),
				self::OTHER_ISSUER
			)
		);
		restore_current_blog();

		$site_admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->assertFalse( is_super_admin( $site_admin ) );
		wp_set_current_user( $site_admin );
		$this->assertFalse( UserLinksScreen::can_manage() );
		$this->post_unlink( $holder, get_current_blog_id() );
		$this->expect_die(
			function (): void {
				$this->screen->unlink_request();
			},
			403
		);
		$this->assertSame( $holder, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );

		wp_set_current_user( $this->manager() );
		$this->assertTrue( is_super_admin() );

		require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
		require_once ABSPATH . 'wp-admin/includes/screen.php';
		set_current_screen( 'users-network' );
		try {
			$this->assertTrue( is_network_admin() );
			$column = $this->screen->render_column( '', UserLinksScreen::COLUMN, $holder );
			$this->assertStringContainsString( 'did:web:issuer.example', $column );
			$this->assertStringContainsString( self::OTHER_ISSUER, $column );
			$this->assert_hides_subject( $column );
		} finally {
			set_current_screen( 'front' );
		}

		$this->post_unlink( $holder, $other );
		$url = $this->screen->unlink_request();
		$this->assertStringContainsString( 'bloclabs_ssi_unlinked=1', $url );

		switch_to_blog( $other );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $other_hash ) );
		restore_current_blog();
		$this->assertSame( $holder, Plugin::instance()->identities()->user_id_for( $this->subject_hash() ), 'the current site keeps its own link' );
	}

	private function manager(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $id );
		}
		return (int) $id;
	}

	private function link_other( int $user_id ): void {
		$settings = Plugin::instance()->settings();
		$linked   = Plugin::instance()->identities()->link(
			hash_hmac( 'sha256', self::OTHER_SUBJECT, $settings->subject_key() ),
			$user_id,
			IdentityRepository::label( self::OTHER_SUBJECT, $settings->subject_key() ),
			self::OTHER_ISSUER
		);
		$this->assertTrue( $linked );
	}

	private function stamp_last_used( string $hash, string $when ): void {
		global $wpdb;
		$updated = $wpdb->update( Schema::identities_table(), array( 'last_login_at' => $when ), array( 'subject_hash' => $hash ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertNotFalse( $updated );
	}

	private function post_unlink( int $user_id, int $blog_id, string $referer = '' ): void {
		$name                      = UserLinksScreen::nonce_name( $blog_id, $user_id );
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_POST                     = array(
			'action'  => UserLinksScreen::ACTION,
			'user_id' => (string) $user_id,
			'blog_id' => (string) $blog_id,
			$name     => wp_create_nonce( UserLinksScreen::nonce_action( $blog_id, $user_id ) ),
		);
		$_REQUEST                  = $_POST; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- builds the request the handler verifies.
		if ( '' !== $referer ) {
			$_REQUEST['_wp_http_referer'] = $referer;
			$_POST['_wp_http_referer']    = $referer;
		}
	}

	private function cli(): Command {
		require_once dirname( __DIR__ ) . '/Stubs/WP_CLI.php';
		\WP_CLI::$lines = array();
		return new Command( Plugin::instance() );
	}

	private function assert_hides_subject( string $output ): void {
		$subject = (string) CapturedLoginEvent::fixture()['subject'];
		$this->assertStringNotContainsString( $subject, $output );
		$this->assertStringNotContainsString( self::OTHER_SUBJECT, $output );
		$this->assertStringNotContainsString( $this->subject_hash(), $output );
		$this->assertStringNotContainsString( $this->subject_hash( self::OTHER_SUBJECT ), $output );
	}

	/**
	 * @param callable():void $request
	 */
	private function expect_die( callable $request, int $status ): void {
		try {
			$request();
			$this->fail( 'The request should have been refused.' );
		} catch ( \WPDieException $e ) {
			$this->assertSame( $status, $e->getCode() );
		}
	}
}
