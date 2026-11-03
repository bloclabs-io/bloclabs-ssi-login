<?php
/**
 * Turns a verified attempt into a WordPress session.
 *
 * Order matters:
 * 1. consume the attempt (compare-and-set: only one request can win);
 * 2. fetch the verified subject from the verifier;
 * 3. check it against the on-chain commitments FireFly delivered;
 * 4. resolve the user, then set the auth cookie.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Identity\UserResolver;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Session\BrowserBinding;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class LoginFinalizer {

	public function __construct(
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

		if ( ! $this->attempts->transition( $attempt, AttemptStatus::Consumed ) ) {
			return new \WP_Error( 'bloclabs_ssi_already_used', __( 'This login request was already used.', 'bloclabs-ssi-login' ), array( 'status' => 409 ) );
		}

		try {
			$result = $this->verifier->fetch_result( (string) $attempt->verifier_ref );
		} catch ( VerifierException $e ) {
			return new \WP_Error( 'bloclabs_ssi_verifier', __( 'The verifier is unavailable. Please try again.', 'bloclabs-ssi-login' ), array( 'status' => 502 ) );
		}

		// The verifier's answer must match what it attested on chain.
		$commitment = Attestation::subject_commitment( $attempt->correlation_id, $result->subject_id );
		if ( null === $attempt->subject_commitment
			|| ! hash_equals( $attempt->subject_commitment, $commitment )
			|| null === $attempt->presentation_hash
			|| ! hash_equals( $attempt->presentation_hash, $result->presentation_hash ) ) {
			do_action( 'bloclabs_ssi_commitment_mismatch', $attempt, $result );
			return new \WP_Error( 'bloclabs_ssi_mismatch', __( 'The verification could not be confirmed.', 'bloclabs-ssi-login' ), array( 'status' => 403 ) );
		}

		$user = $this->users->resolve( $result );
		if ( null === $user ) {
			return new \WP_Error(
				'bloclabs_ssi_not_linked',
				__( 'This credential is not linked to an account here. Log in another way and link it from your profile.', 'bloclabs-ssi-login' ),
				array( 'status' => 403 )
			);
		}

		/**
		 * Veto a login after the credential checked out (2FA policies, bans, maintenance…).
		 *
		 * @param true|\WP_Error $allow
		 * @param \WP_User       $user
		 */
		$allow = apply_filters( 'bloclabs_ssi_allow_login', true, $user, $result );
		if ( is_wp_error( $allow ) ) {
			return $allow;
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		$this->binding->clear();

		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired as wp_signon() does.

		return $user;
	}
}
