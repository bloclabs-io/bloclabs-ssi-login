<?php
/**
 * Links a verified subject to the account that started the attempt; never logs in.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class CredentialLinker {

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptRepository $attempts,
		private readonly IdentityRepository $identities,
		private readonly VerifierClient $verifier,
	) {}

	/** @return true|\WP_Error */
	public function complete( Attempt $attempt ) {
		if ( 'link' !== $attempt->purpose || ! is_user_logged_in() || get_current_user_id() !== $attempt->link_user_id
			|| ! current_user_can( 'read' ) || ( is_multisite() && ! is_user_member_of_blog() ) ) {
			return self::error( 'bloclabs_ssi_profile_auth', __( 'Please reload your profile and log in again.', 'bloclabs-ssi-login' ), 403 );
		}
		if ( AttemptStatus::Verified !== $attempt->status || $attempt->is_expired() ) {
			return self::error( 'bloclabs_ssi_not_verified', __( 'This credential request is not verified or has expired.', 'bloclabs-ssi-login' ), 409 );
		}
		try {
			$result = $this->verifier->fetch_result( (string) $attempt->verifier_ref );
		} catch ( VerifierException $e ) {
			if ( $e->is_transient() ) {
				return self::error( 'bloclabs_ssi_retry', __( 'Still confirming your credential…', 'bloclabs-ssi-login' ), 503 );
			}
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return self::error( 'bloclabs_ssi_verifier', __( 'Please start a new credential request.', 'bloclabs-ssi-login' ), 502 );
		}
		$commitment = Attestation::subject_commitment( $attempt->correlation_id, $attempt->blinding_secret, $result->subject_id );
		if ( null === $attempt->subject_commitment || ! hash_equals( $attempt->subject_commitment, $commitment )
			|| null === $attempt->presentation_hash || ! hash_equals( $attempt->presentation_hash, $result->presentation_hash ) ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			do_action( 'bloclabs_ssi_commitment_mismatch', $attempt, $result );
			return self::error( 'bloclabs_ssi_mismatch', __( 'The verification could not be confirmed.', 'bloclabs-ssi-login' ), 403 );
		}
		$key  = $this->settings->subject_key();
		$hash = hash_hmac( 'sha256', $result->subject_id, $key );
		if ( null !== $this->identities->user_id_for( $hash ) ) {
			$this->attempts->transition( $attempt, AttemptStatus::Failed );
			return self::already_linked();
		}
		// Claim the attempt before any identity mutation. A replay cannot restore an unlinked credential.
		if ( ! $this->attempts->transition( $attempt, AttemptStatus::Consumed ) ) {
			return self::error( 'bloclabs_ssi_already_used', __( 'This credential request was already used.', 'bloclabs-ssi-login' ), 409 );
		}
		// The unique subject key also arbitrates concurrent attempts from different accounts.
		if ( ! $this->identities->link( $hash, $attempt->link_user_id, IdentityRepository::label( $result->subject_id, $key ), $result->issuer ) ) {
			return null !== $this->identities->user_id_for( $hash ) ? self::already_linked()
				: self::error( 'bloclabs_ssi_link_failed', __( 'The credential could not be linked. Please start again.', 'bloclabs-ssi-login' ), 503 );
		}
		return true;
	}

	private static function already_linked(): \WP_Error {
		return self::error( 'bloclabs_ssi_already_linked', __( 'This credential is already linked to an account. Unlink it there before linking it again.', 'bloclabs-ssi-login' ), 409 );
	}

	private static function error( string $code, string $message, int $status ): \WP_Error {
		return new \WP_Error( $code, $message, array( 'status' => $status ) );
	}
}
