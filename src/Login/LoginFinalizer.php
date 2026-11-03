<?php
/**
 * Turns a verified attempt into a WordPress session.
 *
 * Order matters:
 * 1. fetch the verified subject from the verifier; a transient failure
 *    leaves the attempt `verified`, so the browser can retry;
 * 2. check it against the on-chain commitments FireFly delivered;
 * 3. resolve the user and run the same checks a password login gets
 *    (the `authenticate` filter, then `bloclabs_ssi_allow_login`);
 * 4. consume the attempt (compare-and-set: exactly one request wins);
 * 5. only then set the auth cookie.
 * A definitive refusal (mismatch, unlinked credential, veto) moves the
 * attempt to `failed`.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Identity\UserResolver;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Session\BrowserBinding;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class LoginFinalizer {

	/** Error code the browser retries after a short wait. */
	public const RETRY = 'bloclabs_ssi_retry';

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptRepository $attempts,
		private readonly VerifierClient $verifier,
		private readonly UserResolver $users,
		private readonly BrowserBinding $binding,
	) {}

	/**
	 * @return \WP_User|\WP_Error
	 */
	public function finalize( Attempt $attempt ) {
		if ( AttemptStatus::Verified !== $attempt->status || $attempt->is_expired() ) {
			return new \WP_Error( 'bloclabs_ssi_not_verified', __( 'This login request is not verified or has expired.', 'bloclabs-ssi-login' ), array( 'status' => 409 ) );
		}

		try {
			$result = $this->verifier->fetch_result( (string) $attempt->verifier_ref );
		} catch ( VerifierException $e ) {
			// The bridge may attest a moment before it serves the result, or be briefly down: keep the attempt.
			return new \WP_Error( self::RETRY, __( 'Still confirming your credential…', 'bloclabs-ssi-login' ), array( 'status' => 503 ) );
		}

		// The verifier's answer must match what it attested on chain.
		$commitment = Attestation::subject_commitment( $attempt->correlation_id, $result->subject_id );
		if ( null === $attempt->subject_commitment
			|| ! hash_equals( $attempt->subject_commitment, $commitment )
			|| null === $attempt->presentation_hash
			|| ! hash_equals( $attempt->presentation_hash, $result->presentation_hash ) ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			do_action( 'bloclabs_ssi_commitment_mismatch', $attempt, $result );
			return new \WP_Error( 'bloclabs_ssi_mismatch', __( 'The verification could not be confirmed.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}

		$user = $this->users->resolve( $result );
		if ( null === $user ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return new \WP_Error(
				'bloclabs_ssi_not_linked',
				__( 'This credential is not linked to an account here. Log in another way and link it from your profile.', 'bloclabs-ssi-login' ),
				array( 'status' => 403 )
			);
		}

		$refusal = $this->check_user( $user, $result );
		if ( null !== $refusal ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return $refusal;
		}

		if ( ! $this->attempts->transition( $attempt, AttemptStatus::Consumed, array( 'user_id' => $user->ID ) ) ) {
			return new \WP_Error( 'bloclabs_ssi_already_used', __( 'This login request was already used.', 'bloclabs-ssi-login' ), array( 'status' => 409 ) );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, $this->settings->site_is_https() );
		$this->binding->clear();

		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired as wp_signon() does.

		return $user;
	}

	/**
	 * The checks a password login would get, then the plugin's own veto.
	 *
	 * Core's `authenticate` callbacks return early for a WP_User (no password is
	 * checked) but still run the multisite spam check, and lockout or ban plugins
	 * hooked there can refuse. The veto must return exactly true to allow.
	 *
	 * @param \BlocLabs\SsiLogin\Verifier\PresentationResult $result
	 */
	private function check_user( \WP_User $user, $result ): ?\WP_Error {
		/** This filter is documented in wp-includes/pluggable.php */
		$checked = apply_filters( 'authenticate', $user, $user->user_login, '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, as wp_authenticate() applies it.
		if ( is_wp_error( $checked ) ) {
			return self::as_forbidden( $checked );
		}
		if ( ! $checked instanceof \WP_User || $checked->ID !== $user->ID ) {
			return new \WP_Error( 'bloclabs_ssi_refused', __( 'This account cannot log in right now.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}

		/**
		 * Veto a login after the credential checked out (2FA policies, bans, maintenance…).
		 * Return true to allow; anything else refuses, a WP_Error with its own message.
		 *
		 * @param true|false|\WP_Error $allow
		 * @param \WP_User             $user
		 */
		$allow = apply_filters( 'bloclabs_ssi_allow_login', true, $user, $result );
		if ( true === $allow ) {
			return null;
		}
		return is_wp_error( $allow )
			? self::as_forbidden( $allow )
			: new \WP_Error( 'bloclabs_ssi_refused', __( 'This account cannot log in right now.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
	}

	/**
	 * Errors from other plugins rarely carry an HTTP status; REST would answer 500.
	 */
	private static function as_forbidden( \WP_Error $error ): \WP_Error {
		$data = $error->get_error_data();
		if ( ! is_array( $data ) || ! isset( $data['status'] ) ) {
			$error->add_data( array_merge( is_array( $data ) ? $data : array(), array( 'status' => 403 ) ) );
		}
		return $error;
	}
}
