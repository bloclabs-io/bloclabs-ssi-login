<?php
/**
 * POST /firefly/events: FireFly's webhook subscription delivers here.
 *
 * Authentication is a shared secret header that FireFly sends with every
 * delivery (subscription `options.headers`), plus an optional source IP
 * allowlist. The body is only a doorbell: AttestationProcessor re-reads the
 * event from FireFly before acting (see docs/adr/0003-event-consumption.md).
 *
 * Answers: 204 handled or irrelevant (FireFly moves on), 401 bad secret,
 * 503 FireFly could not be asked to confirm (FireFly retries). An event that
 * does not decode also answers 204: a retry would not decode it either, so
 * AttestationProcessor reports it through `bloclabs_ssi_undecodable_event`.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\AttestationProcessor;
use BlocLabs\SsiLogin\FireFly\FireFlyException;
use BlocLabs\SsiLogin\Support\ClientIp;

final class WebhookController {

	public const SECRET_HEADER = 'X-Bloclabs-Ssi-Secret';

	public function __construct(
		private readonly Settings $settings,
		private readonly AttestationProcessor $processor,
	) {}

	public function register_routes(): void {
		register_rest_route(
			Routes::NAMESPACE,
			'/firefly/events',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'handle' ),
				'permission_callback' => array( $this, 'authenticate' ),
			)
		);
	}

	/**
	 * @return true|\WP_Error
	 */
	public function authenticate( \WP_REST_Request $request ) {
		$secret = $this->settings->string( 'webhook_secret' );
		$given  = (string) $request->get_header( self::SECRET_HEADER );

		// No secret configured means the webhook is off, not open.
		if ( strlen( $secret ) < 32 || ! hash_equals( $secret, $given ) ) {
			return new \WP_Error( 'bloclabs_ssi_webhook_auth', 'Unauthorized.', array( 'status' => 401 ) );
		}

		$allowed = $this->settings->string( 'webhook_allowed_ips' );
		if ( '' !== $allowed && ! ClientIp::remote_addr_in( $allowed ) ) {
			return new \WP_Error( 'bloclabs_ssi_webhook_source', 'Forbidden.', array( 'status' => 403 ) );
		}

		return true;
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle( \WP_REST_Request $request ) {
		$body = $request->get_json_params();
		if ( ! is_array( $body ) ) {
			return new \WP_REST_Response( null, 204 );
		}

		// A single event, or a batch (subscription option `batch: true`).
		$events = array_is_list( $body ) ? $body : array( $body );

		try {
			foreach ( $events as $event ) {
				if ( is_array( $event ) ) {
					$this->processor->handle_delivery( $event );
				}
			}
		} catch ( FireFlyException $e ) {
			return new \WP_Error( 'bloclabs_ssi_firefly', 'FireFly unavailable; retry.', array( 'status' => 503 ) );
		}

		return new \WP_REST_Response( null, 204 );
	}
}
