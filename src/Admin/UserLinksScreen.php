<?php
/**
 * Users screen and user edit screen: show linked credentials and unlink them.
 *
 * The profile screen (a person linking or unlinking their own credential) is a
 * separate flow. This screen is the administrator's view of someone else's account.
 *
 * Both the users list and the edit screen are already wrapped in a form, so the
 * Unlink control is a button that submits a separate form printed in the footer
 * (`form="…"`). That keeps the action a POST with its own nonce.
 *
 * On a single site the capability is `edit_users`. On multisite only a network
 * administrator may view or unlink: links are a login factor, and a site
 * administrator must not be able to strip one. Links are stored per site. The
 * network Users screen lists every site the account belongs to; a site's own
 * Users screen lists that site.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Admin;

use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Identity\IdentityRepository;

final class UserLinksScreen {

	public const COLUMN = 'bloclabs_ssi_credentials';

	public const ACTION = 'bloclabs_ssi_unlink_credential';

	/**
	 * Footer forms queued while the column or the edit screen rendered.
	 *
	 * @var array<string, array{blog_id: int, user_id: int}>
	 */
	private array $forms = array();

	/**
	 * Whether the current request has already seen this site's identities table.
	 *
	 * @var array<int, bool>
	 */
	private array $installed = array();

	private bool $forms_printed = false;

	public function __construct( private readonly IdentityRepository $identities ) {}

	public function register(): void {
		add_filter( 'manage_users_columns', array( $this, 'add_column' ) );
		add_filter( 'wpmu_users_columns', array( $this, 'add_column' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'render_column' ), 10, 3 );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'network_admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_head', array( $this, 'print_styles' ) );
		add_action( 'admin_footer', array( $this, 'render_unlink_forms' ) );
		add_action( 'network_admin_footer', array( $this, 'render_unlink_forms' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle_unlink' ) );
	}

	/**
	 * The capability an account needs. On multisite, `can_manage()` also
	 * requires the account to be a network administrator.
	 */
	public static function required_capability(): string {
		return is_multisite() ? 'manage_network_users' : 'edit_users';
	}

	/**
	 * Who may see issuers and last-used times, and who may unlink.
	 *
	 * `is_super_admin()` on a single site means "can delete users", so it is
	 * consulted only on multisite, where it is the network-administrator list.
	 */
	public static function can_manage(): bool {
		if ( is_multisite() ) {
			return is_super_admin() && current_user_can( 'manage_network_users' );
		}
		return current_user_can( 'edit_users' );
	}

	public static function nonce_action( int $blog_id, int $user_id ): string {
		return 'bloclabs_ssi_unlink_' . $blog_id . '_' . $user_id;
	}

	/**
	 * One nonce field name per account and site, so several Unlink forms on the
	 * users list do not share an id.
	 */
	public static function nonce_name( int $blog_id, int $user_id ): string {
		return '_wpnonce_bloclabs_ssi_' . $blog_id . '_' . $user_id;
	}

	/**
	 * @param array<string, string> $columns
	 * @return array<string, string>
	 */
	public function add_column( array $columns ): array {
		if ( self::can_manage() ) {
			$columns[ self::COLUMN ] = __( 'Credentials', 'bloclabs-ssi-login' );
		}
		return $columns;
	}

	/**
	 * @param int|string $user_id User ids arrive from the list table as strings.
	 */
	public function render_column( string $value, string $column, int|string $user_id ): string {
		if ( self::COLUMN !== $column || ! self::can_manage() ) {
			return $value;
		}
		$user_id = (int) $user_id;
		$user    = get_userdata( $user_id );
		$login   = $user instanceof \WP_User ? $user->user_login : (string) $user_id;
		return $this->render_links_markup( $user_id, $login );
	}

	/**
	 * The edit-user screen, not the logged-in user's own profile.
	 */
	public function render_profile_section( \WP_User $user ): void {
		if ( ! self::can_manage() || ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		echo '<h2 id="bloclabs-ssi-linked-credentials">' . esc_html__( 'Linked credentials', 'bloclabs-ssi-login' ) . '</h2>';
		echo '<table class="form-table" role="presentation"><tr>';
		echo '<th scope="row">' . esc_html__( 'Credentials', 'bloclabs-ssi-login' ) . '</th>';
		echo '<td>' . $this->render_links_markup( $user->ID, $user->user_login ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- render_links_markup() escapes.
		echo '</td></tr></table>';
	}

	public function render_notice(): void {
		if ( ! self::can_manage() ) {
			return;
		}
		// A fixed flag set by the redirect. It is not a nonce and it is never printed.
		$raw  = $_GET['bloclabs_ssi_unlinked'] ?? ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized on the next line; only "0" and "1" are used.
		$flag = is_scalar( $raw ) ? sanitize_text_field( wp_unslash( (string) $raw ) ) : '';
		if ( '1' === $flag ) {
			$message = __( 'Credential link removed.', 'bloclabs-ssi-login' );
		} elseif ( '0' === $flag ) {
			$message = __( 'No linked credential to remove.', 'bloclabs-ssi-login' );
		} else {
			return;
		}
		printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html( $message ) );
	}

	/**
	 * Keep a long issuer DID inside the column. The rule is static.
	 */
	public function print_styles(): void {
		if ( ! self::can_manage() || ! function_exists( 'get_current_screen' ) ) {
			return;
		}
		$screen = get_current_screen();
		$ids    = array( 'users', 'user-edit', 'users-network', 'user-edit-network', 'site-users-network' );
		if ( ! $screen instanceof \WP_Screen || ! in_array( $screen->id, $ids, true ) ) {
			return;
		}
		echo '<style id="bloclabs-ssi-links-css">.bloclabs-ssi-links code{word-break:break-all}.bloclabs-ssi-links ul{margin:0 0 .5em}</style>';
	}

	/**
	 * The POST forms the Unlink buttons target. Printed in the footer so they
	 * are not nested inside the users list or the profile form.
	 */
	public function render_unlink_forms(): void {
		if ( $this->forms_printed || ! self::can_manage() ) {
			return;
		}
		$this->forms_printed = true;
		foreach ( $this->forms as $id => $target ) {
			echo '<form id="' . esc_attr( $id ) . '" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="bloclabs-ssi-unlink-form">';
			wp_nonce_field( self::nonce_action( $target['blog_id'], $target['user_id'] ), self::nonce_name( $target['blog_id'], $target['user_id'] ) );
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION ) . '" />';
			echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $target['user_id'] ) . '" />';
			echo '<input type="hidden" name="blog_id" value="' . esc_attr( (string) $target['blog_id'] ) . '" />';
			echo '</form>';
		}
	}

	public function handle_unlink(): void {
		wp_safe_redirect( $this->unlink_request() );
		exit;
	}

	/**
	 * Checks the request and unlinks. Returns the URL to send the administrator
	 * back to. A failed check ends the request with `wp_die()` and leaves the link.
	 */
	public function unlink_request(): string {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' !== $method ) {
			wp_die( esc_html__( 'Unlink must be submitted as a form.', 'bloclabs-ssi-login' ), '', array( 'response' => 405 ) );
		}
		if ( ! self::can_manage() ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to unlink credentials.', 'bloclabs-ssi-login' ), '', array( 'response' => 403 ) );
		}

		$user_id = self::posted_int( 'user_id' );
		$blog_id = self::posted_int( 'blog_id' );
		if ( $user_id < 1 || $blog_id < 1 ) {
			wp_die( esc_html__( 'Missing user.', 'bloclabs-ssi-login' ), '', array( 'response' => 400 ) );
		}
		$this->assert_site( $blog_id );
		check_admin_referer( self::nonce_action( $blog_id, $user_id ), self::nonce_name( $blog_id, $user_id ) );

		$switched = false;
		if ( get_current_blog_id() !== $blog_id ) {
			$switched = switch_to_blog( $blog_id );
			if ( ! $switched ) {
				wp_die( esc_html__( 'Unknown site.', 'bloclabs-ssi-login' ), '', array( 'response' => 400 ) );
			}
		}
		try {
			$user = get_userdata( $user_id );
			if ( ! $user instanceof \WP_User ) {
				wp_die( esc_html__( 'Unknown account.', 'bloclabs-ssi-login' ), '', array( 'response' => 404 ) );
			}
			if ( ! current_user_can( 'edit_user', $user_id ) ) {
				wp_die( esc_html__( 'Sorry, you are not allowed to unlink credentials for this account.', 'bloclabs-ssi-login' ), '', array( 'response' => 403 ) );
			}
			if ( ! $this->identities_installed() ) {
				$flag = '0';
			} else {
				$had = $this->identities->links_for( $user_id );
				if ( array() !== $had ) {
					$this->identities->unlink_user( $user_id );
				}
				$flag = array() === $had ? '0' : '1';
			}
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}

		return $this->redirect_after_unlink( $flag );
	}

	/**
	 * @return list<array{blog_id: int, blog_name: string, links: list<array{user_id: int, subject_label: string, issuer: string, created_at: string, last_login_at: string}>}>
	 */
	private function groups_for( int $user_id ): array {
		if ( ! is_multisite() || ! is_network_admin() ) {
			return array(
				array(
					'blog_id'   => get_current_blog_id(),
					'blog_name' => '',
					'links'     => $this->identities->links_for( $user_id ),
				),
			);
		}

		$blogs = get_blogs_of_user( $user_id );
		if ( ! is_array( $blogs ) ) {
			return array();
		}

		$current = get_current_blog_id();
		$groups  = array();
		foreach ( $blogs as $blog_id => $blog ) {
			$blog_id = (int) $blog_id;
			if ( $blog_id < 1 ) {
				continue;
			}
			$links = $this->links_on_blog( $blog_id, $user_id, $current );
			if ( array() === $links ) {
				continue;
			}
			$name     = is_object( $blog ) && isset( $blog->blogname ) ? (string) $blog->blogname : '';
			$groups[] = array(
				'blog_id'   => $blog_id,
				'blog_name' => $name,
				'links'     => $links,
			);
		}
		return $groups;
	}

	/**
	 * @return list<array{user_id: int, subject_label: string, issuer: string, created_at: string, last_login_at: string}>
	 */
	private function links_on_blog( int $blog_id, int $user_id, int $current ): array {
		if ( $blog_id === $current ) {
			return $this->links_if_installed( $user_id );
		}
		if ( ! switch_to_blog( $blog_id ) ) {
			return array();
		}
		try {
			return $this->links_if_installed( $user_id );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * @return list<array{user_id: int, subject_label: string, issuer: string, created_at: string, last_login_at: string}>
	 */
	private function links_if_installed( int $user_id ): array {
		if ( ! $this->identities_installed() ) {
			return array();
		}
		return $this->identities->links_for( $user_id );
	}

	/**
	 * True when this site has the identities table.
	 *
	 * Activation creates it for the current site only. The network Users screen
	 * switches into every site an account belongs to, including sites where the
	 * plugin was never activated, and those have nothing to query.
	 */
	private function identities_installed(): bool {
		$blog_id = get_current_blog_id();
		if ( isset( $this->installed[ $blog_id ] ) ) {
			return $this->installed[ $blog_id ];
		}
		global $wpdb;
		$table                       = Schema::identities_table();
		$found                       = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->installed[ $blog_id ] = $table === $found;
		return $this->installed[ $blog_id ];
	}

	private function render_links_markup( int $user_id, string $login ): string {
		$groups = array();
		foreach ( $this->groups_for( $user_id ) as $group ) {
			if ( array() !== $group['links'] ) {
				$groups[] = $group;
			}
		}
		if ( array() === $groups ) {
			return '<p class="bloclabs-ssi-links">' . esc_html__( 'None', 'bloclabs-ssi-login' ) . '</p>';
		}

		$html = '<div class="bloclabs-ssi-links">';
		foreach ( $groups as $group ) {
			if ( '' !== $group['blog_name'] ) {
				$html .= '<p><strong>' . esc_html( $group['blog_name'] ) . '</strong></p>';
			}
			$html .= '<ul>';
			foreach ( $group['links'] as $link ) {
				$issuer = '' !== $link['issuer'] ? $link['issuer'] : __( 'Unknown issuer', 'bloclabs-ssi-login' );
				$html  .= '<li><code>' . esc_html( $issuer ) . '</code><br />';
				$html  .= esc_html(
					sprintf(
						/* translators: %s: when this credential last logged in, or "Never". */
						__( 'Last used: %s', 'bloclabs-ssi-login' ),
						$this->format_last_used( $link['last_login_at'] )
					)
				);
				if ( '' !== $link['subject_label'] ) {
					$html .= '<br /><span class="description">' . esc_html( $link['subject_label'] ) . '</span>';
				}
				$html .= '</li>';
			}
			$html .= '</ul>';
			if ( current_user_can( 'edit_user', $user_id ) ) {
				$html .= $this->unlink_button( $group['blog_id'], $user_id, $login, $group['blog_name'] );
			}
		}
		$html .= '</div>';
		return $html;
	}

	private function unlink_button( int $blog_id, int $user_id, string $login, string $blog_name ): string {
		$form_id                 = 'bloclabs-ssi-unlink-' . $blog_id . '-' . $user_id;
		$this->forms[ $form_id ] = array(
			'blog_id' => $blog_id,
			'user_id' => $user_id,
		);
		if ( '' !== $blog_name ) {
			$accessible = sprintf(
				/* translators: 1: WordPress username, 2: site name. */
				__( 'credentials for %1$s on %2$s', 'bloclabs-ssi-login' ),
				$login,
				$blog_name
			);
		} else {
			$accessible = sprintf(
				/* translators: %s: WordPress username. */
				__( 'credentials for %s', 'bloclabs-ssi-login' ),
				$login
			);
		}
		return '<button type="submit" class="button button-small" form="' . esc_attr( $form_id ) . '">'
			. esc_html__( 'Unlink', 'bloclabs-ssi-login' )
			. ' <span class="screen-reader-text">' . esc_html( $accessible ) . '</span></button>';
	}

	private function format_last_used( string $mysql ): string {
		if ( '' === $mysql || str_starts_with( $mysql, '0000-00-00' ) ) {
			return __( 'Never', 'bloclabs-ssi-login' );
		}
		// last_login_at is stored with gmdate(); mysql2date() would read that as local time.
		$stored = date_create( $mysql, new \DateTimeZone( 'UTC' ) );
		if ( false === $stored ) {
			return $mysql;
		}
		$format = trim( (string) get_option( 'date_format' ) . ' ' . (string) get_option( 'time_format' ) );
		$shown  = wp_date( '' !== $format ? $format : 'Y-m-d H:i:s', $stored->getTimestamp() );
		return is_string( $shown ) && '' !== $shown ? $shown : $mysql;
	}

	private function assert_site( int $blog_id ): void {
		if ( ! is_multisite() ) {
			if ( get_current_blog_id() !== $blog_id ) {
				wp_die( esc_html__( 'Unknown site.', 'bloclabs-ssi-login' ), '', array( 'response' => 400 ) );
			}
			return;
		}
		if ( ! get_site( $blog_id ) ) {
			wp_die( esc_html__( 'Unknown site.', 'bloclabs-ssi-login' ), '', array( 'response' => 400 ) );
		}
	}

	private function redirect_after_unlink( string $flag ): string {
		$fallback = is_network_admin() ? network_admin_url( 'users.php' ) : admin_url( 'users.php' );
		$referer  = wp_get_referer();
		$target   = is_string( $referer ) && '' !== $referer ? wp_validate_redirect( $referer, $fallback ) : $fallback;
		return add_query_arg( 'bloclabs_ssi_unlinked', $flag, $target );
	}

	private static function posted_int( string $key ): int {
		if ( ! isset( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- the caller verifies the nonce after reading the ids it is bound to.
			return 0;
		}
		$value = wp_unslash( $_POST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- absint() below; nonce is checked by the caller.
		return is_scalar( $value ) ? absint( $value ) : 0;
	}
}
