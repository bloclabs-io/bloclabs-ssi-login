<?php
/**
 * Pull path: asks FireFly for recent attestations when a push did not arrive.
 *
 * It runs from the status endpoint, at most once per interval per attempt
 * (a compare-and-set on checked_at), so a hundred polling browsers do not
 * become a hundred FireFly queries a second. In `poll` event mode it is the
 * only path; in `webhook` mode it starts after `poll_fallback_after` seconds.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;

final class EventReconciler {

	private const CHECK_INTERVAL = 3;

	public function __construct(
		private readonly Settings $settings,
		private readonly FireFlyClient $firefly,
		private readonly AttestationProcessor $processor,
		private readonly AttemptRepository $attempts,
	) {}

	public function should_poll( Attempt $attempt ): bool {
		if ( '' === $this->settings->string( 'firefly_listener_id' ) ) {
			return false;
		}
		if ( Settings::EVENT_MODE_POLL === $this->settings->string( 'event_mode' ) ) {
			return true;
		}
		return time() - $attempt->created_at >= $this->settings->int( 'poll_fallback_after' );
	}

	/**
	 * @return int Attestations applied.
	 */
	public function reconcile( Attempt $attempt ): int {
		if ( ! $this->should_poll( $attempt ) || ! $this->attempts->claim_check( $attempt, self::CHECK_INTERVAL ) ) {
			return 0;
		}

		try {
			$events = $this->firefly->blockchain_events(
				$this->settings->string( 'firefly_listener_id' ),
				$this->settings->string( 'attestation_event' ),
				$attempt->created_at - 5
			);
		} catch ( FireFlyException $e ) {
			return 0; // The browser keeps polling; the next check retries.
		}

		$applied = 0;
		foreach ( $events as $chain_event ) {
			if ( ! is_array( $chain_event ) ) {
				continue;
			}
			// Same shape as a webhook delivery, so the decoder is shared.
			$event = array(
				'id'              => 'poll:' . ( $chain_event['id'] ?? '' ),
				'type'            => 'blockchain_event_received',
				'blockchainEvent' => $chain_event,
			);
			if ( AttestationProcessor::APPLIED === $this->processor->apply( $event ) ) {
				++$applied;
			}
		}
		return $applied;
	}
}
