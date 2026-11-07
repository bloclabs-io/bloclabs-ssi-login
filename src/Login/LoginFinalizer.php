<?php
/**
 * Turns a verified attempt into a WordPress session.
 *
 * The checks every verified attempt passes (the verifier's result against the
 * chain, the user against the login filters) live in LoginChecks, shared with
 * the agent's TokenIssuer. What is the browser's alone:
 *
 * 1. the user is resolved by the site's linking policy, so an unknown
 *    subject may get an account (auto_provision);
 * 2. the attempt is consumed (compare-and-set: exactly one request wins);
 * 3. only then the auth cookie is set and `wp_login` fires.
 * A definitive refusal (mismatch, unlinked credential, veto) moves the
 * attempt to `failed`.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\Identity\UserResolver;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Session\BrowserBinding;

final class LoginFinalizer {

	/** Error code the browser retries after a short wait. */
	public const RETRY = LoginChecks::RETRY;

	/** The attempts this finalizer completes: a login, not a profile link or an agent's token. */
	public const PURPOSE = 'login';

	public function __construct(
		private readonly AttemptRepository $attempts,
		private readonly LoginChecks $checks,
		private readonly UserResolver $users,
		private readonly BrowserBinding $binding,
	) {}

	/**
	 * @return \WP_User|\WP_Error A WP_Error with code RETRY leaves the attempt verified.
	 */
	public function finalize( Attempt $attempt ) {
		$refusal = $this->checks->verified( $attempt, self::PURPOSE );
		if ( null !== $refusal ) {
			return $refusal;
		}

		$result = $this->checks->result( $attempt );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$user = $this->users->resolve( $result );
		if ( is_wp_error( $user ) ) {
			// Another request is still creating this subject's account: the browser retries.
			return $user;
		}
		if ( null === $user ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return new \WP_Error(
				'bloclabs_ssi_not_linked',
				__( 'This credential is not linked to an account here. Log in another way and link it from your profile.', 'bloclabs-ssi-login' ),
				array( 'status' => 403 )
			);
		}

		$refusal = $this->checks->check_user( $user, $result );
		if ( null !== $refusal ) {
			$this->users->undo_provision( $user->ID );
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return $refusal;
		}

		if ( ! $this->attempts->transition( $attempt, AttemptStatus::Consumed, array( 'user_id' => $user->ID ) ) ) {
			return new \WP_Error( 'bloclabs_ssi_already_used', __( 'This login request was already used.', 'bloclabs-ssi-login' ), array( 'status' => 409 ) );
		}

		wp_set_current_user( $user->ID );
		// Core reads the cookie it picks by is_ssl(), so the cookie must be set by is_ssl() too, as wp_signon()
		// does: behind a TLS proxy that hides HTTPS from PHP, a cookie set by the home URL's scheme is never read.
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		$this->binding->clear();

		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired as wp_signon() does.

		return $user;
	}
}
