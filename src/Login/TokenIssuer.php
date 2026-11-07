<?php
/**
 * Turns a verified agent attempt into an application token (ADR 0007 §3).
 *
 * The checks every verified attempt passes (the verifier's result against the
 * chain, the user against the login filters) live in LoginChecks, shared with
 * the browser's LoginFinalizer. What is the agent's alone, in order:
 *
 * 1. the attempt was opened for an agent (the browser's cannot become tokens);
 * 2. the account is resolved by the agent credential's rules: `acts_for` and
 *    the principal's opt-in, else the agent's own linked key; nothing is ever
 *    provisioned (UserResolver::resolve_agent());
 * 3. `bloclabs_ssi_agent_token` may narrow the scope or the lifetime, or refuse;
 * 4. scope = requested ∩ the credential's `scope` ∩ the site's `agent_scopes`,
 *    and the lifetime is the TTL bounded by the credential's expiry; empty or
 *    past means refuse;
 * 5. the attempt is consumed (compare-and-set: exactly one request wins) and
 *    the token row written in the same request: one attestation, at most one
 *    token, ever;
 * 6. the token is returned once. No cookie, no `wp_login`: there is no
 *    interactive session. `bloclabs_ssi_agent_token_issued` fires instead.
 *
 * A definitive refusal moves the attempt to `failed`; a transient verifier
 * failure leaves it `verified` for the agent to retry.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Identity\AgentCredential;
use BlocLabs\SsiLogin\Identity\UserResolver;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Verifier\PresentationResult;

final class TokenIssuer {

	/** Error code the agent retries after `poll_after`: the attempt is still verified. */
	public const RETRY = LoginChecks::RETRY;

	/** The attempts this issuer completes: opened by `/agent/initiate`, never by the login page. */
	public const PURPOSE = 'agent';

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptRepository $attempts,
		private readonly LoginChecks $checks,
		private readonly UserResolver $users,
		private readonly TokenStore $tokens,
	) {}

	/**
	 * @param Attempt      $attempt   A verified agent attempt.
	 * @param list<string> $requested The scope names the agent asked for when it opened the attempt.
	 * @return IssuedToken|\WP_Error A WP_Error with code RETRY leaves the attempt verified.
	 */
	public function issue( Attempt $attempt, array $requested ) {
		$refusal = $this->checks->verified( $attempt, self::PURPOSE );
		if ( null !== $refusal ) {
			return $refusal;
		}

		$result = $this->checks->result( $attempt );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$account = $this->users->resolve_agent( $result );
		if ( null === $account ) {
			// Not linked, or the principal has not opted in: one answer for both, so a credential from a
			// trusted issuer cannot probe which subjects hold accounts here.
			return $this->refuse( $attempt, 'bloclabs_ssi_not_linked', __( 'No account here accepts a token for this credential.', 'bloclabs-ssi-login' ) );
		}
		$user = $account->user;

		$refusal = $this->checks->check_user( $user, $result );
		if ( null !== $refusal ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return $refusal;
		}

		$now        = time();
		$scope      = Scope::grant( Scope::names( $requested ), AgentCredential::scope( $result ), Scope::site( $this->settings ) );
		$expires_at = $now + $this->settings->agent_token_ttl();
		if ( null !== $result->expires_at ) {
			// A token never outlives the credential it came from.
			$expires_at = min( $expires_at, $result->expires_at );
		}

		/**
		 * Narrow an agent token, or refuse it, after the credential and the account checked out.
		 * Return the grant (`scope`, a list of names; `expires_at`, Unix time), narrowed as you
		 * like: it can only shrink. A WP_Error refuses with its own message; anything else refuses.
		 *
		 * @param array{scope: list<string>, expires_at: int}|\WP_Error|false $grant
		 * @param \WP_User                                                      $user   The account the token would act as.
		 * @param PresentationResult                                            $result The agent credential, as verified.
		 * @param Attempt                                                       $attempt
		 */
		$grant = apply_filters(
			'bloclabs_ssi_agent_token',
			array(
				'scope'      => $scope,
				'expires_at' => $expires_at,
			),
			$user,
			$result,
			$attempt
		);
		if ( is_wp_error( $grant ) ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return LoginChecks::as_forbidden( $grant );
		}
		if ( ! is_array( $grant ) ) {
			return $this->refuse( $attempt, 'bloclabs_ssi_refused', __( 'This account cannot log in right now.', 'bloclabs-ssi-login' ) );
		}
		$scope = Scope::grant( Scope::names( $grant['scope'] ?? array() ), null, $scope );
		if ( isset( $grant['expires_at'] ) && is_int( $grant['expires_at'] ) ) {
			$expires_at = min( $expires_at, $grant['expires_at'] );
		}

		if ( array() === $scope ) {
			return $this->refuse( $attempt, 'bloclabs_ssi_scope', __( 'None of the requested scope is allowed for this agent.', 'bloclabs-ssi-login' ) );
		}
		if ( $expires_at <= $now ) {
			return $this->refuse( $attempt, 'bloclabs_ssi_token_lifetime', __( 'The credential expires too soon for a token.', 'bloclabs-ssi-login' ) );
		}

		$token = new IssuedToken(
			AgentToken::generate(),
			$user->ID,
			$account->delegated,
			$this->users->subject_hash( $result->subject_id ),
			AgentCredential::label( $result, $this->settings->subject_key() ),
			$result->issuer,
			$scope,
			$attempt->correlation_id,
			$attempt->tx_ref,
			$attempt->firefly_event_id,
			$now,
			$expires_at
		);

		// Consume first, then write: a lost race or a failed write leaves no token, never two (threat A6).
		if ( ! $this->attempts->transition( $attempt, AttemptStatus::Consumed, array( 'user_id' => $user->ID ) ) ) {
			return new \WP_Error( 'bloclabs_ssi_already_used', __( 'This login request was already used.', 'bloclabs-ssi-login' ), array( 'status' => 409 ) );
		}
		if ( ! $this->tokens->store( $token ) ) {
			// The attestation is spent and no token exists: the agent presents again.
			return new \WP_Error( 'bloclabs_ssi_token_storage', __( 'The token could not be stored. Please start again.', 'bloclabs-ssi-login' ), array( 'status' => 503 ) );
		}

		/**
		 * An application token was issued. The row carries the token's hash, never the token.
		 *
		 * @param array<string, scalar|null> $row     The tokens table row, as stored.
		 * @param \WP_User                   $user    The account the token acts as.
		 * @param PresentationResult         $result  The agent credential, as verified.
		 * @param Attempt                    $attempt The attempt it came from.
		 */
		do_action( 'bloclabs_ssi_agent_token_issued', $token->to_row(), $user, $result, $attempt );

		return $token;
	}

	/**
	 * A definitive refusal: the attempt is failed, and the agent must present again.
	 */
	private function refuse( Attempt $attempt, string $code, string $message ): \WP_Error {
		$this->attempts->transition( $attempt, AttemptStatus::Failed );
		return new \WP_Error( $code, $message, array( 'status' => 403 ) );
	}
}
