<?php
/**
 * POST /initiate: open a login attempt and a presentation request.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Session\BrowserBinding;
use BlocLabs\SsiLogin\Support\ClientIp;
use BlocLabs\SsiLogin\Verifier\PresentationRequest;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class InitiateController extends BrowserController {

	private const RATE_WINDOW = 600;

	public function __construct(
		Settings $settings,
		AttemptRepository $attempts,
		BrowserBinding $binding,
		private readonly VerifierClient $verifier,
	) {
		parent::__construct( $settings, $attempts, $binding );
	}

	public function register_routes(): void {
		register_rest_route(
			Routes::NAMESPACE,
			'/initiate',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'handle' ),
				'permission_callback' => array( $this, 'check_page_request' ),
				'args'                => array(
					'redirect_to' => array(
						'type'              => 'string',
						'required'          => false,
						'sanitize_callback' => 'esc_url_raw',
					),
				),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle( \WP_REST_Request $request ) {
		$unavailable = new \WP_Error( 'bloclabs_ssi_unavailable', __( 'Credential login is unavailable right now.', 'bloclabs-ssi-login' ), array( 'status' => 503 ) );

		// The bridge's result route returns claims: never talk to a bridge that does not authenticate us.
		if ( '' === $this->settings->string( 'verifier_auth_header' ) ) {
			return $unavailable;
		}

		// No usable client address means no rate limit, so no attempt.
		$ip_hash = ClientIp::hash( $this->settings );
		if ( null === $ip_hash ) {
			return $unavailable;
		}
		// Checked before the row exists, so a client already over the cap costs no cookie and no row ...
		$limited = $this->rate_limited( $ip_hash );
		if ( null !== $limited ) {
			return $limited;
		}

		$ttl      = max( 60, min( 600, $this->settings->int( 'attempt_ttl' ) ) );
		$redirect = (string) $request->get_param( 'redirect_to' );
		$redirect = '' !== $redirect ? wp_validate_redirect( $redirect, '' ) : '';

		try {
			$binding = $this->binding->issue();
		} catch ( \RuntimeException $e ) {
			return $unavailable;
		}

		try {
			$attempt = $this->attempts->open( $binding, $ip_hash, $ttl, '' !== $redirect ? $redirect : null );
		} catch ( \RuntimeException $e ) {
			// No row (a missing or read-only table), so no attempt for the cookie to bind, and no 500 with a path in it.
			$this->binding->clear();
			return $unavailable;
		}

		// ... and again by this row's rank in the window, so a parallel burst cannot overshoot.
		$limited = $this->rate_limited( $ip_hash, $attempt );
		if ( null !== $limited ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return $limited;
		}

		try {
			$offer = $this->verifier->create_request(
				new PresentationRequest(
					$attempt->correlation_id,
					$attempt->nonce,
					$attempt->blinding_secret,
					$this->settings->string( 'credential_query' ),
					$attempt->expires_at
				)
			);
		} catch ( VerifierException $e ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return $unavailable;
		}

		if ( ! $this->attempts->set_verifier_ref( $attempt, $offer->verifier_ref ) ) {
			// Without the bridge's id the attempt could never complete: fail it here, not at /complete.
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return $unavailable;
		}

		$response = new \WP_REST_Response(
			array(
				'attempt'    => $attempt->public_id,
				'wallet_url' => $offer->wallet_url,
				'dc_api'     => $offer->dc_api,
				'expires_in' => $ttl,
				'poll_after' => 2,
			),
			201
		);
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}

	/**
	 * The per-client cap (an IPv4 address or an IPv6 /64) and the site-wide cap
	 * that backs it, so that neither one flooding client nor many keep the
	 * verifier and the attempts table busy.
	 *
	 * @param Attempt|null $attempt After the insert: counts up to this attempt, its rank in the window.
	 */
	private function rate_limited( string $ip_hash, ?Attempt $attempt = null ): ?\WP_Error {
		// Once the new row exists the count includes it, and that row may be the cap-th one.
		$own = null === $attempt ? 0 : 1;

		if ( $this->attempts->count_recent( self::RATE_WINDOW, $ip_hash, $attempt ) - $own >= $this->settings->int( 'max_pending_per_ip' ) ) {
			return new \WP_Error( 'bloclabs_ssi_rate_limited', __( 'Too many login requests. Please wait a few minutes.', 'bloclabs-ssi-login' ), array( 'status' => 429 ) );
		}
		if ( $this->attempts->count_recent( self::RATE_WINDOW, null, $attempt ) - $own >= $this->settings->int( 'max_pending_total' ) ) {
			return new \WP_Error( 'bloclabs_ssi_rate_limited', __( 'Credential login is busy right now. Please wait a few minutes.', 'bloclabs-ssi-login' ), array( 'status' => 429 ) );
		}
		return null;
	}
}
