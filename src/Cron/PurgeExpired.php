<?php
/**
 * Hourly housekeeping: expire stale attempts, delete attempts older than a day.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Cron;

use BlocLabs\SsiLogin\Session\AttemptRepository;

final class PurgeExpired {

	public const HOOK = 'bloclabs_ssi_purge';

	private const KEEP = DAY_IN_SECONDS;

	public function __construct( private readonly AttemptRepository $attempts ) {}

	public function register(): void {
		add_action( self::HOOK, array( $this, 'run' ) );
	}

	public function run(): int {
		return $this->attempts->purge( (int) apply_filters( 'bloclabs_ssi_attempt_retention', self::KEEP ) );
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
