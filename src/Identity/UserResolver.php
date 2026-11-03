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
use BlocLabs\SsiLogin\Verifier\PresentationResult;

final class UserResolver {

	public function __construct(
		private readonly Settings $settings,
		private readonly IdentityRepository $identities,
	) {}

	public function subject_hash( string $subject_id ): string {
		return hash_hmac( 'sha256', $subject_id, $this->settings->subject_key() );
	}

	public function resolve( PresentationResult $result ): ?\WP_User {
		$hash    = $this->subject_hash( $result->subject_id );
		$user_id = $this->identities->user_id_for( $hash );

		if ( null === $user_id && Settings::AUTO_PROVISION === $this->settings->string( 'linking_policy' ) ) {
			$user_id = $this->provision( $result, $hash );
		}

		/**
		 * Last word on which user a verified subject becomes (or null to refuse).
		 *
		 * @param int|null           $user_id
		 * @param PresentationResult $result
		 */
		$user_id = apply_filters( 'bloclabs_ssi_resolve_user', $user_id, $result );

		$user = is_int( $user_id ) ? get_userdata( $user_id ) : false;
		if ( ! $user instanceof \WP_User ) {
			return null;
		}

		$this->identities->touch( $hash );
		return $user;
	}

	/**
	 * A self-registering stranger never gets a role that can manage the site.
	 */
	private function safe_role(): string {
		$role = get_role( $this->settings->string( 'default_role' ) );
		if ( null === $role || $role->has_cap( 'manage_options' ) || $role->has_cap( 'edit_users' ) || $role->has_cap( 'promote_users' ) ) {
			return 'subscriber';
		}
		return $role->name;
	}

	private function provision( PresentationResult $result, string $hash ): ?int {
		$data = array(
			'user_login'   => 'ssi-' . substr( $hash, 0, 12 ),
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

		$user_id = wp_insert_user( wp_slash( $data ) );
		if ( is_wp_error( $user_id ) ) {
			return null;
		}

		if ( ! $this->identities->link( $hash, $user_id, IdentityRepository::label( $result->subject_id ), $result->issuer ) ) {
			// Lost a race with a concurrent provision of the same subject: use the winner.
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $user_id );
			return $this->identities->user_id_for( $hash );
		}

		return $user_id;
	}
}
