<?php
/**
 * Shared checks for the three routes the login page calls.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\BrowserBinding;

abstract class BrowserController {

	public const TOKEN_HEADER = 'X-Bloclabs-Ssi-Token';

	public function __construct(
		protected readonly Settings $settings,
		protected readonly AttemptRepository $attempts,
		protected readonly BrowserBinding $binding,
	) {}

	abstract public function register_routes(): void;

	/**
	 * Plugin enabled and the request carries the login page's token.
	 *
	 * The token is a cross-site request check only: it is the same for every
	 * visitor (see PageToken). The cookie binding is what ties an attempt to a
	 * browser.
	 *
	 * @return true|\WP_Error
	 */
	public function check_page_request( \WP_REST_Request $request ) {
		if ( ! $this->settings->enabled() ) {
			return new \WP_Error( 'bloclabs_ssi_disabled', __( 'Credential login is disabled.', 'bloclabs-ssi-login' ), array( 'status' => 404 ) );
		}
		if ( ! PageToken::verify( (string) $request->get_header( self::TOKEN_HEADER ) ) ) {
			return new \WP_Error( 'bloclabs_ssi_nonce', __( 'Please reload the login page and try again.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}
		return true;
	}

	/**
	 * The attempt named in the request, if this browser holds its binding cookie.
	 * Unknown and foreign attempts look the same (404): no oracle for guessing ids.
	 *
	 * @return Attempt|\WP_Error
	 */
	protected function bound_attempt( string $public_id ) {
		$attempt = 1 === preg_match( '/^[a-f0-9]{32}$/', $public_id ) ? $this->attempts->find_by_public_id( $public_id ) : null;
		if ( null === $attempt || ! $this->binding->matches( $attempt ) ) {
			return new \WP_Error( 'bloclabs_ssi_unknown', __( 'Unknown login request.', 'bloclabs-ssi-login' ), array( 'status' => 404 ) );
		}
		return $attempt;
	}

	/**
	 * @return array<string, mixed>
	 */
	protected static function attempt_arg(): array {
		return array(
			'type'     => 'string',
			'required' => true,
			'pattern'  => '^[a-f0-9]{32}$',
		);
	}
}
