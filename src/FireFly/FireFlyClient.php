<?php
/**
 * Thin client for the FireFly core REST API (/api/v1/namespaces/{ns}/...).
 *
 * FireFly core has no authentication of its own. Reach it over a private
 * network, or put an authenticating proxy in front and set
 * BLOCLABS_SSI_FIREFLY_AUTH_HEADER (for example "Bearer …").
 *
 * The URL comes from an administrator, never from a visitor, so the client
 * uses wp_remote_request() rather than wp_safe_remote_request(): the safe
 * variant refuses the private addresses FireFly is meant to live on.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

use BlocLabs\SsiLogin\Config\Settings;

final class FireFlyClient {

	private const TIMEOUT = 5;

	public function __construct( private readonly Settings $settings ) {}

	/**
	 * One event, with the object it references embedded
	 * (`blockchainEvent` for blockchain_event_received).
	 *
	 * @return array<string, mixed>
	 */
	public function event( string $event_id ): array {
		return $this->get( 'events/' . rawurlencode( $event_id ), array( 'fetchreference' => 'true' ) );
	}

	/**
	 * Blockchain events from one listener since a time, newest first.
	 *
	 * @return list<array<string, mixed>>
	 */
	public function blockchain_events( string $listener_id, string $name, int $since, int $limit = 50 ): array {
		return $this->get(
			'blockchainevents',
			array(
				'listener'  => $listener_id,
				'name'      => $name,
				// FireFly filter syntax: an operator prefix on the value.
				'timestamp' => '>=' . gmdate( 'Y-m-d\TH:i:s\Z', $since ),
				'sort'      => '-timestamp',
				'limit'     => (string) $limit,
			)
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function status(): array {
		return $this->request( 'GET', $this->root() . '/api/v1/status' );
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	public function subscriptions(): array {
		return $this->get( 'subscriptions' );
	}

	/**
	 * Creates the webhook subscription that delivers LoginAttested events here.
	 *
	 * @param array<string, string> $headers Sent with every delivery (the shared secret).
	 * @return array<string, mixed>
	 */
	public function create_webhook_subscription( string $name, string $url, string $listener_id, array $headers ): array {
		return $this->post(
			'subscriptions',
			array(
				'name'      => $name,
				'transport' => 'webhooks',
				'filter'    => array(
					'events'          => 'blockchain_event_received',
					'blockchainevent' => array( 'listener' => $listener_id ),
				),
				'options'   => array(
					'firstEvent' => 'newest',
					'url'        => $url,
					'method'     => 'POST',
					'headers'    => $headers,
					// Ack only after WordPress answers 2xx, so a failed delivery is retried.
					'fastack'    => false,
					// Deliveries are independent (WordPress is idempotent), so let a few run in parallel.
					'readAhead'  => 25,
					'retry'      => array(
						'enabled'      => true,
						'count'        => 5,
						'initialDelay' => '250ms',
						'maxDelay'     => '10s',
					),
				),
			)
		);
	}

	/**
	 * @param array<string, string> $query
	 * @return array<mixed>
	 */
	public function get( string $path, array $query = array() ): array {
		return $this->request( 'GET', $this->ns_url( $path, $query ) );
	}

	/**
	 * @param array<string, mixed> $body
	 * @return array<mixed>
	 */
	public function post( string $path, array $body ): array {
		return $this->request( 'POST', $this->ns_url( $path ), $body );
	}

	/**
	 * @param array<string, string> $query
	 */
	private function ns_url( string $path, array $query = array() ): string {
		$url = sprintf(
			'%s/api/v1/namespaces/%s/%s',
			$this->root(),
			rawurlencode( $this->settings->string( 'firefly_namespace' ) ),
			ltrim( $path, '/' )
		);
		return $query ? $url . '?' . http_build_query( $query, '', '&', PHP_QUERY_RFC3986 ) : $url;
	}

	private function root(): string {
		return untrailingslashit( $this->settings->string( 'firefly_url' ) );
	}

	/**
	 * @param array<string, mixed>|null $body
	 * @return array<mixed>
	 */
	private function request( string $method, string $url, ?array $body = null ): array {
		$headers = array( 'Accept' => 'application/json' );
		$auth    = $this->settings->string( 'firefly_auth_header' );
		if ( '' !== $auth ) {
			$headers['Authorization'] = $auth;
		}
		if ( null !== $body ) {
			$headers['Content-Type'] = 'application/json';
		}

		$response = wp_remote_request(
			$url,
			array(
				'method'      => $method,
				'timeout'     => self::TIMEOUT,
				'redirection' => 0,
				'headers'     => $headers,
				'body'        => null === $body ? null : wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			throw new FireFlyException( 'FireFly is unreachable: ' . esc_html( $response->get_error_message() ), 0 );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( $code < 200 || $code >= 300 ) {
			$message = is_array( $data ) && isset( $data['error'] ) ? (string) $data['error'] : 'HTTP ' . $code;
			throw new FireFlyException( 'FireFly error: ' . esc_html( $message ), (int) $code );
		}

		return is_array( $data ) ? $data : array();
	}
}
