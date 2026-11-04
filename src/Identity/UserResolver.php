<?php
/**
 * Decides which WordPress user a verified subject logs in as.
 *
 * - link_only (default): only subjects already linked to an account log in.
 *   Linking happens while logged in with an existing method (roadmap: a
 *   "Link a credential" button on the profile screen).
 * - auto_provision: an unknown subject gets a new account with the default role.
 *
 * Matching on an e-mail claim is deliberately not offered: unless the issuer
 * is trusted to have verified that address, it hands accounts to whoever can
 * get a credential saying so.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Login\LoginFinalizer;
use BlocLabs\SsiLogin\Verifier\PresentationResult;

final class UserResolver {

	/**
	 * Users this request provisioned, by id: true when it created the account,
	 * false when it adopted a network account that no site held (see provision()).
	 *
	 * @var array<int, bool>
	 */
	private array $provisioned = array();

	public function __construct(
		private readonly Settings $settings,
		private readonly IdentityRepository $identities,
	) {}

	public function subject_hash( string $subject_id ): string {
		return hash_hmac( 'sha256', $subject_id, $this->settings->subject_key() );
	}

	/**
	 * @return \WP_User|\WP_Error|null The user to log in; a WP_Error the browser retries
	 *                                 when the answer is not known yet (another request is
	 *                                 still creating this subject's account, or the link could
	 *                                 not be stored); null when the subject has no account here.
	 */
	public function resolve( PresentationResult $result ) {
		$hash    = $this->subject_hash( $result->subject_id );
		$user_id = $this->identities->user_id_for( $hash );

		// A link to a deleted user is no link: drop it, so the subject can be linked or provisioned again.
		if ( null !== $user_id && ! get_userdata( $user_id ) instanceof \WP_User ) {
			$this->identities->unlink_user( $user_id );
			$user_id = null;
		}

		if ( null === $user_id && Settings::AUTO_PROVISION === $this->settings->string( 'linking_policy' ) ) {
			$user_id = $this->provision( $result, $hash );
			if ( is_wp_error( $user_id ) ) {
				return $user_id;
			}
		}

		/**
		 * Last word on which user a verified subject becomes (or null to refuse).
		 *
		 * @param int|null           $user_id
		 * @param PresentationResult $result
		 */
		$chosen = apply_filters( 'bloclabs_ssi_resolve_user', $user_id, $result );

		$user = is_int( $chosen ) ? get_userdata( $chosen ) : false;

		// An account this request made for a login the filter then refused, or sent elsewhere, must not stay behind.
		if ( is_int( $user_id ) && ( ! $user instanceof \WP_User || $user->ID !== $user_id ) ) {
			$this->undo_provision( $user_id );
		}
		if ( ! $user instanceof \WP_User ) {
			return null;
		}

		$this->identities->touch( $hash );
		return $user;
	}

	/**
	 * A self-registering stranger never gets a role that can manage the site.
	 *
	 * @param string $requested Role name; empty for the configured default.
	 */
	private function safe_role( string $requested = '' ): string {
		$role = get_role( '' !== $requested ? $requested : $this->settings->string( 'default_role' ) );
		if ( null === $role || $role->has_cap( 'manage_options' ) || $role->has_cap( 'edit_users' ) || $role->has_cap( 'promote_users' ) ) {
			return 'subscriber';
		}
		return $role->name;
	}

	/**
	 * Creates and links an account for a new subject.
	 *
	 * The login is deterministic (`ssi-` and the start of the subject hash), so
	 * a login that already exists is this subject's own account in one of three
	 * states: linked by a concurrent request that got there first (use it); not
	 * linked yet by that request (retry, never "not linked"); or, on multisite,
	 * stranded without a site, because wp_delete_user() only removes a network
	 * user from the current site, or because the subject already has an account
	 * on another site of the network under a shared subject key (adopt it).
	 *
	 * @return int|\WP_Error|null The user id; a WP_Error to retry; null to refuse.
	 */
	private function provision( PresentationResult $result, string $hash ) {
		$login = 'ssi-' . substr( $hash, 0, 12 );
		$data  = array(
			'user_login'   => $login,
			'user_pass'    => wp_generate_password( 64, true, true ),
			'display_name' => isset( $result->claims['name'] ) && is_string( $result->claims['name'] ) ? sanitize_text_field( $result->claims['name'] ) : '',
			'role'         => $this->safe_role(),
		);

		/**
		 * Adjust the account created for a new subject. Return null to refuse.
		 *
		 * @param array<string, mixed>|null $data
		 * @param PresentationResult        $result
		 */
		$data = apply_filters( 'bloclabs_ssi_provision_user_data', $data, $result );
		if ( ! is_array( $data ) ) {
			return null;
		}

		// Whatever the filter did: always a new user (no ID means insert, not update), never a powerful role.
		unset( $data['ID'], $data['user_level'] );
		$data['role'] = $this->safe_role( isset( $data['role'] ) ? (string) $data['role'] : '' );

		$created = true;
		$user_id = wp_insert_user( wp_slash( $data ) );
		if ( is_wp_error( $user_id ) ) {
			if ( 'existing_user_login' !== $user_id->get_error_code() ) {
				return null;
			}
			$linked = $this->identities->user_id_for( $hash );
			if ( null !== $linked ) {
				return $linked;
			}
			$user_id = $this->stranded( $login, (string) ( $data['user_login'] ?? '' ) );
			if ( null === $user_id ) {
				return self::retry();
			}
			$created = false;
			// The network can refuse this site the account (can_add_user_to_blog): then it is not linked here.
			if ( is_wp_error( add_user_to_blog( get_current_blog_id(), $user_id, $data['role'] ) ) ) {
				return null;
			}
		}

		if ( ! $this->identities->link( $hash, $user_id, IdentityRepository::label( $result->subject_id, $this->settings->subject_key() ), $result->issuer ) ) {
			$winner = $this->identities->user_id_for( $hash );
			if ( $winner === $user_id ) {
				return $user_id;
			}
			// Lost a race with a concurrent provision of the same subject (use the winner), or the
			// link could not be stored at all (retry): either way this account is of no use.
			$this->discard( $user_id, $created );
			return $winner ?? self::retry();
		}

		$this->provisioned[ $user_id ] = $created;
		return $user_id;
	}

	/**
	 * On multisite: the network user holding this subject's deterministic login
	 * that no site holds. Only the generated login counts; one the provisioning
	 * filter chose may belong to someone else.
	 */
	private function stranded( string $generated, string $login ): ?int {
		if ( ! is_multisite() || $login !== $generated ) {
			return null;
		}
		$user = get_user_by( 'login', $login );
		if ( ! $user instanceof \WP_User || is_user_member_of_blog( $user->ID ) ) {
			return null;
		}
		return $user->ID;
	}

	/**
	 * Removes an account this request provisioned, when the login it was made for
	 * is then refused: otherwise every later attempt would find it and fail again.
	 */
	public function undo_provision( int $user_id ): void {
		if ( ! isset( $this->provisioned[ $user_id ] ) ) {
			return;
		}
		$created = $this->provisioned[ $user_id ];
		unset( $this->provisioned[ $user_id ] );
		$this->identities->unlink_user( $user_id );
		$this->discard( $user_id, $created );
	}

	/**
	 * An account this request created goes away everywhere: on multisite
	 * wp_delete_user() would only remove it from this site and leave its login
	 * taken. An adopted account, or one that another site of the network adopted
	 * while this request ran (see stranded()), only leaves this site.
	 */
	private function discard( int $user_id, bool $created ): void {
		if ( ! $created || $this->held_elsewhere( $user_id ) ) {
			remove_user_from_blog( $user_id, get_current_blog_id() );
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/user.php';
		if ( is_multisite() ) {
			require_once ABSPATH . 'wp-admin/includes/ms.php';
			wpmu_delete_user( $user_id );
			return;
		}
		wp_delete_user( $user_id );
	}

	/**
	 * On multisite: whether a site other than this one holds the account. A site
	 * that adopts it after this check is left with a link to a deleted user, which
	 * resolve() treats as no link, so that subject's next login there provisions again.
	 */
	private function held_elsewhere( int $user_id ): bool {
		if ( ! is_multisite() ) {
			return false;
		}
		foreach ( array_keys( get_blogs_of_user( $user_id, true ) ) as $blog_id ) {
			if ( get_current_blog_id() !== (int) $blog_id ) {
				return true;
			}
		}
		return false;
	}

	private static function retry(): \WP_Error {
		return new \WP_Error( LoginFinalizer::RETRY, __( 'Still setting up your account…', 'bloclabs-ssi-login' ), array( 'status' => 503 ) );
	}
}
