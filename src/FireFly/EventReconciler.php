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
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;

final class EventReconciler {

	private const CHECK_INTERVAL = 15;
	private const PAGE_SIZE      = 50;
	// 20 pages: 1,000 attestations within one attempt's lifetime is far beyond a single site's login rate.
	private const MAX_PAGES = 20;
	// One status request never spends longer than this on FireFly.
	private const TIME_BUDGET = 8.0;

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

		global $wpdb;
		// Connection-scoped lock: no lease can expire while a slow HTTP scan is still running.
		$lock = 'ssi_poll_' . md5( Schema::attempts_table() );
		if ( '1' !== (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', $lock ) ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			return 0;
		}
		try {
			if ( (int) get_option( 'bloclabs_ssi_poll_after', 0 ) > time() ) {
				return 0;
			}
			return $this->scan( $attempt );
		} finally {
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		}
	}

	private function scan( Attempt $attempt ): int {
		// Shared cooldown, also acting as a circuit breaker on transport failures.
		update_option( 'bloclabs_ssi_poll_after', time() + 30, false );
		$applied = 0;
		$started = microtime( true );
		for ( $page = 0; $page < self::MAX_PAGES; $page++ ) {
			if ( $page > 0 && microtime( true ) - $started > self::TIME_BUDGET ) {
				break; // The next poll continues; settled attempts are skipped as duplicates.
			}
			try {
				// Every attestation since this attempt started, newest first, a page at a time.
				$events = $this->firefly->blockchain_events(
					$this->settings->string( 'firefly_listener_id' ),
					$this->settings->string( 'attestation_event' ),
					$attempt->created_at - 3600,
					self::PAGE_SIZE,
					$page * self::PAGE_SIZE
				);
			} catch ( FireFlyException $e ) {
				return $applied; // The browser keeps polling; the next check retries.
			}

			foreach ( $events as $chain_event ) {
				if ( ! is_array( $chain_event ) ) {
					continue;
				}
				// Same shape as a webhook delivery, so the decoder is shared. Settling other attempts on the way is fine.
				$event = array(
					'id'              => 'poll:' . ( $chain_event['id'] ?? '' ),
					'type'            => 'blockchain_event_received',
					'blockchainEvent' => $chain_event,
				);
				if ( AttestationProcessor::APPLIED === $this->processor->apply( $event ) ) {
					++$applied;
				}
			}

			if ( count( $events ) < self::PAGE_SIZE ) {
				break;
			}

			// Found ours: no need to read older pages.
			$current = $this->attempts->find_by_public_id( $attempt->public_id );
			if ( null === $current || AttemptStatus::Pending !== $current->status ) {
				break;
			}
		}
		update_option( 'bloclabs_ssi_poll_after', time() + 3, false );
		return $applied;
	}
}
