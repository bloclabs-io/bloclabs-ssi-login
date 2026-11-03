<?php
/**
 * Applies FireFly events to login attempts. Shared by the webhook receiver
 * and the polling fallback, so both paths enforce the same rules.
 *
 * The webhook body is treated as a doorbell, never as evidence: the event is
 * always re-read from FireFly by id before anything changes. A leaked webhook
 * secret lets an attacker ring the bell, not forge an attestation.
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

		try {
			$event = $this->firefly->event( $event_id );
		} catch ( FireFlyException $e ) {
			if ( $e->is_not_found() ) {
				return self::IGNORED; // Not an event FireFly knows: forged, or from another node.
			}
			throw $e;
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
			$this->report_undecodable( $event );
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

	/**
	 * An event from our own listener that does not decode means the contract and
	 * the decoder disagree. Polling would miss it too, so make it visible.
	 *
	 * @param array<string, mixed> $event
	 */
	private function report_undecodable( array $event ): void {
		$chain_event = is_array( $event['blockchainEvent'] ?? null ) ? $event['blockchainEvent'] : array();
		$listener    = strtolower( $this->settings->string( 'firefly_listener_id' ) );
		$removed     = true === ( $chain_event['info']['removed'] ?? false );
		if ( '' === $listener || $removed || strtolower( (string) ( $chain_event['listener'] ?? '' ) ) !== $listener
			|| $this->settings->string( 'attestation_event' ) !== ( $chain_event['name'] ?? null ) ) {
			return;
		}

		/**
		 * An attestation event from the configured listener could not be decoded.
		 *
		 * @param array<string, mixed> $event
		 */
		do_action( 'bloclabs_ssi_undecodable_event', $event );
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'bloclabs-ssi-login: undecodable LoginAttested event ' . (string) ( $event['id'] ?? '?' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
