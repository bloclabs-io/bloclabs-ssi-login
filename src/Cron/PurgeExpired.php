<?php
/**
 * Hourly housekeeping for attempts and the agent token audit trail.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Cron;

use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\TokenRepository;

final class PurgeExpired {

	public const HOOK = 'bloclabs_ssi_purge';

	private const KEEP = DAY_IN_SECONDS;

	public function __construct(
		private readonly AttemptRepository $attempts,
		private readonly TokenRepository $tokens = new TokenRepository(),
	) {}

	public function register(): void {
		add_action( self::HOOK, array( $this, 'run' ) );
	}

	public function run(): int {
		$deleted = $this->attempts->purge( (int) apply_filters( 'bloclabs_ssi_attempt_retention', self::KEEP ) );
		return $deleted + $this->tokens->purge( (int) apply_filters( 'bloclabs_ssi_token_retention', 30 * DAY_IN_SECONDS ) );
	}

	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::HOOK );
		}
	}

	public static function unschedule(): void {
		wp_clear_scheduled_hook( self::HOOK );
	}
}
