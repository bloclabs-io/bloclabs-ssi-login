<?php
/**
 * Applies FireFly events to login attempts. Shared by the webhook receiver
 * and the polling fallback, so both paths enforce the same rules.
 *
 * The webhook body is treated as a doorbell, not as evidence: with
 * `confirm_events` on (the default) the event is re-read from FireFly by ID
 * before anything changes. A leaked webhook secret then lets an attacker ring
 * the bell, not forge an attestation.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;

final class AttestationProcessor {

	public const APPLIED   = 'applied';
	public const IGNORED   = 'ignored';
	public const DUPLICATE = 'duplicate';

	public function __construct(
		private readonly Settings $settings,
		private readonly FireFlyClient $firefly,
		private readonly EventDecoder $decoder,
		private readonly AttemptRepository $attempts,
	) {}

	/**
	 * Handles an event delivered by a webhook (untrusted body).
	 *
	 * @param array<string, mixed> $delivered
	 * @throws FireFlyException When FireFly cannot be asked to confirm; the caller answers 503 so FireFly retries.
	 */
	public function handle_delivery( array $delivered ): string {
		$event_id = isset( $delivered['id'] ) && is_string( $delivered['id'] ) ? $delivered['id'] : '';
		if ( '' === $event_id ) {
			return self::IGNORED;
		}

		if ( $this->settings->bool( 'confirm_events' ) ) {
			try {
				$event = $this->firefly->event( $event_id );
			} catch ( FireFlyException $e ) {
				if ( $e->is_not_found() ) {
					return self::IGNORED; // Not an event FireFly knows: forged or from another node.
				}
				throw $e;
			}
		} else {
			$event = $delivered;
		}

		return $this->apply( $event );
	}

	/**
	 * Handles an event read from FireFly directly (trusted).
	 *
	 * @param array<string, mixed> $event
	 */
	public function apply( array $event ): string {
		$attestation = $this->decoder->decode( $event );
		if ( null === $attestation ) {
			return self::IGNORED;
		}

		$attempt = $this->attempts->find_by_correlation_id( $attestation->correlation_id );
		if ( null === $attempt ) {
			return self::IGNORED;
		}
		if ( AttemptStatus::Pending !== $attempt->status ) {
			return self::DUPLICATE;
		}

		$to = AttemptStatus::Rejected;
		if ( $attestation->is_verified() && ! $attempt->is_expired() ) {
			$to = AttemptStatus::Verified;
		} elseif ( $attestation->is_verified() ) {
			$to = AttemptStatus::Expired;
		}

		$changed = $this->attempts->transition(
			$attempt,
			$to,
			array(
				'firefly_event_id'   => $attestation->event_id,
				'tx_ref'             => $attestation->tx_ref,
				'subject_commitment' => $attestation->subject_commitment,
				'presentation_hash'  => $attestation->presentation_hash,
			)
		);

		if ( $changed ) {
			/**
			 * Fires when an on-chain attestation settles a login attempt.
			 *
			 * @param Attestation   $attestation What the verifier attested.
			 * @param AttemptStatus $status      The attempt's new status.
			 */
			do_action( 'bloclabs_ssi_attested', $attestation, $to );
		}

		return $changed ? self::APPLIED : self::DUPLICATE;
	}
}
