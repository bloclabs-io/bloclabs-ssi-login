<?php
/**
 * The captured FireFly v1.5.0 LoginAttested event, with one attempt's correlation id swapped in.
 *
 * The fixture's subject commitment is sha256(correlation_id ":" subject_id). Swapping the
 * correlation without recomputing that commitment would make the captured log contradict
 * itself, and every successful login would fail the plugin's own check. The presentation
 * hash and the rest of the log stay as captured.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration\Support;

final class CapturedLoginEvent {

	/**
	 * @return array<string, mixed>
	 */
	public static function fixture(): array {
		static $fixture = null;
		if ( null === $fixture ) {
			$path    = dirname( __DIR__, 2 ) . '/fixtures/firefly-login-attested.json';
			$decoded = json_decode( (string) file_get_contents( $path ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local fixture.
			if ( ! is_array( $decoded ) ) {
				throw new \RuntimeException( 'Could not read the captured FireFly event.' );
			}
			$fixture = $decoded;
		}
		return $fixture;
	}

	/**
	 * The `GET /events/{id}?fetchreference=true` body for one attempt.
	 *
	 * @return array<string, mixed>
	 */
	public static function delivery_for( string $correlation_id, bool $removed = false ): array {
		$fixture        = self::fixture();
		$event          = $fixture['delivery'];
		$correlation_id = strtolower( $correlation_id );
		$commitment     = hash( 'sha256', $correlation_id . ':' . $fixture['subject'] );

		$event['blockchainEvent']['output']['correlationId']     = '0x' . $correlation_id;
		$event['blockchainEvent']['output']['subjectCommitment'] = '0x' . $commitment;
		if ( isset( $event['blockchainEvent']['info']['topics'][1] ) ) {
			// topics[1] is the indexed correlationId in the captured log.
			$event['blockchainEvent']['info']['topics'][1] = '0x' . $correlation_id;
		}
		if ( $removed ) {
			$event['blockchainEvent']['info']['removed'] = true;
		}

		return $event;
	}
}
