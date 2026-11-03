<?php
/**
 * HTTP client for the verifier bridge (docs/BRIDGE-API.md).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

use BlocLabs\SsiLogin\Config\Settings;

final class BridgeClient implements VerifierClient {

	private const TIMEOUT = 5;

	public function __construct( private readonly Settings $settings ) {}

	public function create_request( PresentationRequest $request ): PresentationOffer {
		return PresentationOffer::from_array( $this->call( 'POST', '/v1/presentation-requests', $request->to_array() ) );
	}

	public function fetch_result( string $verifier_ref ): PresentationResult {
		return PresentationResult::from_array(
			$this->call( 'GET', '/v1/presentation-requests/' . rawurlencode( $verifier_ref ) . '/result' )
		);
	}

	/**
	 * @param array<string, mixed>|null $body
	 * @return array<string, mixed>
	 */
	private function call( string $method, string $path, ?array $body = null ): array {
		$headers = array( 'Accept' => 'application/json' );
		$auth    = $this->settings->string( 'verifier_auth_header' );
		if ( '' !== $auth ) {
			$headers['Authorization'] = $auth;
		}
		if ( null !== $body ) {
			$headers['Content-Type'] = 'application/json';
		}

		// Administrator-configured, usually private, address: see FireFlyClient on wp_remote_request().
		$response = wp_remote_request(
			untrailingslashit( $this->settings->string( 'verifier_url' ) ) . $path,
			array(
				'method'      => $method,
				'timeout'     => self::TIMEOUT,
				'redirection' => 0,
				'headers'     => $headers,
				'body'        => null === $body ? null : wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			throw new VerifierException( 'The verifier is unreachable: ' . esc_html( $response->get_error_message() ) );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( $code < 200 || $code >= 300 || ! is_array( $data ) ) {
			throw new VerifierException( 'The verifier answered HTTP ' . (int) $code . '.', (int) $code );
		}

		return $data;
	}
}
