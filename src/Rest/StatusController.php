<?php
/**
 * GET /status/{attempt}: where the attempt stands. Safe to poll; changes no
 * session. In poll mode, or once the webhook is overdue, it asks FireFly.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\EventReconciler;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Session\BrowserBinding;

final class StatusController extends BrowserController {

	public function __construct(
		Settings $settings,
		AttemptRepository $attempts,
		BrowserBinding $binding,
		private readonly EventReconciler $reconciler,
	) {
		parent::__construct( $settings, $attempts, $binding );
	}

	public function register_routes(): void {
		register_rest_route(
			Routes::NAMESPACE,
			'/status/(?P<attempt>[a-f0-9]{32})',
			array(
				'methods'             => \WP_REST_Server::READABLE,
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

		if ( AttemptStatus::Pending === $attempt->status ) {
			if ( $attempt->is_expired() ) {
				$this->attempts->transition( $attempt, AttemptStatus::Expired );
			} else {
				$this->reconciler->reconcile( $attempt );
			}
			// A webhook may have settled it meanwhile, too.
			$attempt = $this->attempts->find_by_public_id( $attempt->public_id ) ?? $attempt;
		}

		$response = new \WP_REST_Response(
			array(
				'status'     => $attempt->status->public_label(),
				'expires_in' => max( 0, $attempt->expires_at - time() ),
				'poll_after' => 2,
			)
		);
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}
}
