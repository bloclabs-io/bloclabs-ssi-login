<?php
/**
 * POST /complete: log the browser in once its attempt is verified.
 *
 * A separate POST, not a side effect of /status, so that a GET never sets
 * an auth cookie and the final step carries the page nonce.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Login\LoginFinalizer;
use BlocLabs\SsiLogin\Identity\CredentialLinker;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\BrowserBinding;

final class CompleteController extends BrowserController {

	public function __construct(
		Settings $settings,
		AttemptRepository $attempts,
		BrowserBinding $binding,
		private readonly LoginFinalizer $finalizer,
		private readonly CredentialLinker $linker,
	) {
		parent::__construct( $settings, $attempts, $binding );
	}

	public function register_routes(): void {
		register_rest_route(
			Routes::NAMESPACE,
			'/complete',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'handle' ),
				'permission_callback' => array( $this, 'check_page_request' ),
				'args'                => array( 'attempt' => self::attempt_arg() ),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle( \WP_REST_Request $request ) {
		$attempt = $this->bound_attempt( (string) $request->get_param( 'attempt' ) );
		if ( is_wp_error( $attempt ) ) {
			return $attempt;
		}

		if ( 'link' === $attempt->purpose ) {
			$allowed = ProfileAuthorization::check( $request );
			if ( is_wp_error( $allowed ) ) {
				return $allowed;
			}
			$result = $this->linker->complete( $attempt );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			$response = new \WP_REST_Response( array( 'linked' => true ) );
			$response->header( 'Cache-Control', 'no-store' );
			return $response;
		}

		$user = $this->finalizer->finalize( $attempt );
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$requested = (string) $attempt->redirect_to;
		$target    = '' !== $requested ? $requested : admin_url();
		/** This filter is documented in wp-login.php */
		$redirect = apply_filters( 'login_redirect', $target, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, applied as wp-login.php does.
		$redirect = wp_validate_redirect( (string) $redirect, admin_url() );

		$response = new \WP_REST_Response( array( 'redirect_to' => $redirect ) );
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}
}
