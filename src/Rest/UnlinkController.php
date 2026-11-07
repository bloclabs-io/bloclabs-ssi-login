<?php
/**
 * Self-service unlink, always scoped to the authenticated account.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Identity\IdentityRepository;

final class UnlinkController {

	public function __construct( private readonly IdentityRepository $identities ) {}

	public function register_routes(): void {
		register_rest_route(
			Routes::NAMESPACE,
			'/profile/unlink',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => array( ProfileAuthorization::class, 'check' ),
				'callback'            => array( $this, 'handle' ),
				'args'                => array(
					'identity' => array(
						'type'     => 'integer',
						'minimum'  => 1,
						'required' => true,
					),
				),
			)
		);
	}

	/** @return \WP_REST_Response|\WP_Error */
	public function handle( \WP_REST_Request $request ) {
		if ( ! $this->identities->unlink_owned( (int) $request->get_param( 'identity' ), get_current_user_id() ) ) {
			return new \WP_Error( 'bloclabs_ssi_unknown_identity', __( 'Credential link not found.', 'bloclabs-ssi-login' ), array( 'status' => 404 ) );
		}
		$response = new \WP_REST_Response( array( 'unlinked' => true ) );
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}
}
