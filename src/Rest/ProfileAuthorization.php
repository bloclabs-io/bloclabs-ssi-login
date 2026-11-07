<?php
/**
 * Session-bound authorization for self-service credential changes.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

final class ProfileAuthorization {

	/** @return true|\WP_Error */
	public static function check( \WP_REST_Request $request ) {
		if ( ! is_user_logged_in() || ! current_user_can( 'read' )
			|| ( is_multisite() && ! is_user_member_of_blog() )
			|| ! wp_verify_nonce( (string) $request->get_header( 'X-WP-Nonce' ), 'wp_rest' ) ) {
			return new \WP_Error( 'bloclabs_ssi_profile_auth', __( 'Please reload your profile and log in again.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}
		return true;
	}
}
