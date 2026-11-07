<?php
/**
 * What every verified attempt passes before it becomes anything.
 *
 * The browser's LoginFinalizer and the agent's TokenIssuer share these
 * steps, in this order (ADR 0007 §3), so neither copies the other:
 *
 * 1. the attempt is `verified` and not expired;
 * 2. the verifier's result is fetched; a transient failure leaves the attempt
 *    `verified` and the caller retries, a definitive one fails it;
 * 3. the result is checked against the on-chain commitments FireFly delivered
 *    (SECURITY-MODEL threat 7);
 * 4. the resolved user gets the checks a password login gets (the
 *    `wp_authenticate` action, the `wp_authenticate_user` and `authenticate`
 *    filters, then `bloclabs_ssi_allow_login`; threat 16).
 *
 * Which user, and what the attempt turns into, stay with the caller.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Verifier\PresentationResult;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class LoginChecks {

	/** Error code the caller retries after a short wait: the attempt is still verified. */
	public const RETRY = 'bloclabs_ssi_retry';

	public function __construct(
		private readonly AttemptRepository $attempts,
		private readonly VerifierClient $verifier,
	) {}

	/**
	 * Step 1: only a verified, unexpired attempt opened for this purpose goes on.
	 * A login attempt cannot become a token, nor an agent attempt a session
	 * (ADR 0007, threat A5); a profile link is neither.
	 *
	 * @param string $purpose The attempt purpose the caller completes.
	 */
	public function verified( Attempt $attempt, string $purpose ): ?\WP_Error {
		if ( $purpose !== $attempt->purpose || AttemptStatus::Verified !== $attempt->status || $attempt->is_expired() ) {
			return new \WP_Error( 'bloclabs_ssi_not_verified', __( 'This login request is not verified or has expired.', 'bloclabs-ssi-login' ), array( 'status' => 409 ) );
		}
		return null;
	}

	/**
	 * Steps 2 and 3: the verifier's answer, once it matches what it attested on chain.
	 *
	 * @return PresentationResult|\WP_Error A WP_Error with code RETRY leaves the attempt verified;
	 *                                      any other failed it.
	 */
	public function result( Attempt $attempt ) {
		try {
			$result = $this->verifier->fetch_result( (string) $attempt->verifier_ref );
		} catch ( VerifierException $e ) {
			if ( $e->is_transient() ) {
				// The bridge may attest a moment before it serves the result, or be briefly down: keep the attempt.
				return new \WP_Error( self::RETRY, __( 'Still confirming your credential…', 'bloclabs-ssi-login' ), array( 'status' => 503 ) );
			}
			// 404 and other definitive answers: the result is gone or never existed.
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return new \WP_Error( 'bloclabs_ssi_verifier', __( 'The verification result is no longer available. Please start again.', 'bloclabs-ssi-login' ), array( 'status' => 502 ) );
		}

		$commitment = Attestation::subject_commitment( $attempt->correlation_id, $attempt->blinding_secret, $result->subject_id );
		if ( null === $attempt->subject_commitment
			|| ! hash_equals( $attempt->subject_commitment, $commitment )
			|| null === $attempt->presentation_hash
			|| ! hash_equals( $attempt->presentation_hash, $result->presentation_hash ) ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			do_action( 'bloclabs_ssi_commitment_mismatch', $attempt, $result );
			return new \WP_Error( 'bloclabs_ssi_mismatch', __( 'The verification could not be confirmed.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}

		return $result;
	}

	/**
	 * Step 4: the checks a password login would get, then the plugin's own veto.
	 *
	 * wp_signon() fires `wp_authenticate`, and core's password callbacks apply
	 * `wp_authenticate_user` before they return a user; both are where lockout,
	 * ban and disabled-account plugins refuse. Those callbacks return early for
	 * a WP_User, so this method applies `wp_authenticate_user` itself (with an
	 * empty password, as nothing was typed) before the `authenticate` filter,
	 * which still runs the multisite spam check and whatever plugins hook there.
	 * The veto must return exactly true to allow.
	 */
	public function check_user( \WP_User $user, PresentationResult $result ): ?\WP_Error {
		$login    = $user->user_login;
		$password = '';
		/** This action is documented in wp-includes/user.php */
		do_action_ref_array( 'wp_authenticate', array( &$login, &$password ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core action, fired as wp_signon() does.

		/** This filter is documented in wp-includes/user.php */
		$refusal = self::refusal( apply_filters( 'wp_authenticate_user', $user, '' ), $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, as wp_authenticate_username_password() applies it.
		if ( null !== $refusal ) {
			return $refusal;
		}

		/** This filter is documented in wp-includes/pluggable.php */
		$refusal = self::refusal( apply_filters( 'authenticate', $user, $user->user_login, '' ), $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, as wp_authenticate() applies it.
		if ( null !== $refusal ) {
			return $refusal;
		}

		/**
		 * Veto a login after the credential checked out (2FA policies, bans, maintenance…).
		 * Return true to allow; anything else refuses, a WP_Error with its own message.
		 * Runs for browser logins and for agent tokens alike.
		 *
		 * @param true|false|\WP_Error $allow
		 * @param \WP_User             $user
		 * @param PresentationResult   $result
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
	 * What a login filter answered, as a refusal or null to go on: a WP_Error
	 * refuses with its own message, and so does anything but the same user.
	 *
	 * @param mixed $checked
	 */
	private static function refusal( $checked, \WP_User $user ): ?\WP_Error {
		if ( is_wp_error( $checked ) ) {
			return self::as_forbidden( $checked );
		}
		if ( ! $checked instanceof \WP_User || $checked->ID !== $user->ID ) {
			return new \WP_Error( 'bloclabs_ssi_refused', __( 'This account cannot log in right now.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}
		return null;
	}

	/**
	 * Errors from other plugins rarely carry an HTTP status; REST would answer 500.
	 */
	public static function as_forbidden( \WP_Error $error ): \WP_Error {
		$data = $error->get_error_data();
		if ( ! is_array( $data ) || ! isset( $data['status'] ) ) {
			$error->add_data( array_merge( is_array( $data ) ? $data : array(), array( 'status' => 403 ) ) );
		}
		return $error;
	}
}
