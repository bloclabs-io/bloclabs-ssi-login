<?php
/**
 * wp bloclabs-ssi <status|subscribe|purge>
 *
 * phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter -- WP-CLI passes ($args, $assoc_args) to every subcommand.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Cli;

use BlocLabs\SsiLogin\FireFly\FireFlyException;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Rest\WebhookController;

/**
 * Operates SSI Login from the command line.
 */
final class Command {

	public function __construct( private readonly Plugin $plugin ) {}

	public static function register( Plugin $plugin ): void {
		\WP_CLI::add_command( 'bloclabs-ssi', new self( $plugin ) );
	}

	/**
	 * Checks FireFly reachability, the listener setting and the webhook subscriptions.
	 *
	 * ## OPTIONS
	 *
	 * [--webhook-url=<url>]
	 * : Expected delivery URL when using an internal address.
	 *
	 * [--name=<name>]
	 * : Expected subscription name (default bloclabs-ssi-login).
	 *
	 * ## EXAMPLES
	 *
	 *     wp bloclabs-ssi status
	 *
	 * @param list<string>          $args
	 * @param array<string, string> $assoc
	 */
	public function status( array $args, array $assoc ): void {
		$settings = $this->plugin->settings();
		\WP_CLI::log( 'Enabled:        ' . ( $settings->enabled() ? 'yes' : 'no' ) );
		\WP_CLI::log( 'Event mode:     ' . $settings->string( 'event_mode' ) );
		\WP_CLI::log( 'Listener:       ' . ( '' !== $settings->string( 'firefly_listener_id' ) ? $settings->string( 'firefly_listener_id' ) : '(not set)' ) );
		\WP_CLI::log( 'Webhook secret: ' . ( strlen( $settings->string( 'webhook_secret' ) ) >= 32 ? 'set' : 'MISSING (webhook refuses all deliveries)' ) );

		try {
			$status = $this->plugin->firefly()->status();
			\WP_CLI::log( 'FireFly:        reachable, namespace ' . ( $status['namespace']['name'] ?? '?' ) );
			$webhook  = $assoc['webhook-url'] ?? rest_url( 'bloclabs-ssi/v1/firefly/events' );
			$listener = $this->plugin->firefly()->get( 'contracts/listeners/' . rawurlencode( $settings->string( 'firefly_listener_id' ) ) );
			if ( empty( $listener['location']['address'] ) ) {
				\WP_CLI::warning( 'The contract listener has no address binding.' );
			} elseif ( strtolower( (string) $listener['location']['address'] ) !== strtolower( $settings->string( 'attestor_address' ) ) ) {
				\WP_CLI::warning( 'The listener address differs from attestor_address.' );
			}
			$found = false;
			foreach ( $this->plugin->firefly()->subscriptions() as $sub ) {
				if ( 'webhooks' === ( $sub['transport'] ?? '' ) && ( $assoc['name'] ?? 'bloclabs-ssi-login' ) === ( $sub['name'] ?? '' ) ) {
					$found   = true;
					$headers = array_change_key_case( (array) ( $sub['options']['headers'] ?? array() ), CASE_LOWER );
					if ( ( $sub['options']['url'] ?? '' ) !== $webhook || ! hash_equals( $settings->string( 'webhook_secret' ), (string) ( $headers[ strtolower( WebhookController::SECRET_HEADER ) ] ?? '' ) ) ) {
						\WP_CLI::warning( 'Subscription URL or secret differs; run subscribe to update it.' );
					}
					\WP_CLI::log( sprintf( 'Subscription:   %s → %s', $sub['name'] ?? '?', $sub['options']['url'] ?? '?' ) );
				}
			}
			if ( ! $found ) {
				\WP_CLI::warning( 'Webhook subscription is missing.' );
			}
			\WP_CLI::log( 'This site:      ' . $webhook );
		} catch ( FireFlyException $e ) {
			\WP_CLI::warning( $e->getMessage() );
		}
	}

	/**
	 * Creates the FireFly webhook subscription that delivers LoginAttested events here.
	 *
	 * ## OPTIONS
	 *
	 * [--webhook-url=<url>]
	 * : Where FireFly should POST. Defaults to this site's REST URL; pass an
	 *   internal address when FireFly reaches WordPress over a private network.
	 *   (Not `--url`: WP-CLI keeps that global option for itself, so a command
	 *   never receives it.)
	 *
	 * [--name=<name>]
	 * : Subscription name.
	 * ---
	 * default: bloclabs-ssi-login
	 * ---
	 *
	 * @param list<string>          $args
	 * @param array<string, string> $assoc
	 */
	public function subscribe( array $args, array $assoc ): void {
		$settings = $this->plugin->settings();
		$listener = $settings->string( 'firefly_listener_id' );
		$secret   = $settings->string( 'webhook_secret' );

		if ( '' === $listener ) {
			\WP_CLI::error( 'Set the contract listener ID first (firefly_listener_id).' );
		}
		if ( strlen( $secret ) < 32 ) {
			\WP_CLI::error( 'Set a webhook secret of at least 32 characters first (BLOCLABS_SSI_WEBHOOK_SECRET).' );
		}

		try {
			$sub = $this->plugin->firefly()->create_webhook_subscription(
				$assoc['name'] ?? 'bloclabs-ssi-login',
				$assoc['webhook-url'] ?? rest_url( 'bloclabs-ssi/v1/firefly/events' ),
				$listener,
				array( WebhookController::SECRET_HEADER => $secret )
			);
		} catch ( FireFlyException $e ) {
			\WP_CLI::error( $e->getMessage() );
		}

		\WP_CLI::success( 'Subscription ' . ( $sub['id'] ?? '?' ) . ' saved.' );
	}

	/**
	 * Expires stale attempts and deletes old ones now.
	 *
	 * @param list<string>          $args
	 * @param array<string, string> $assoc
	 */
	public function purge( array $args, array $assoc ): void {
		$deleted = $this->plugin->attempts()->purge( DAY_IN_SECONDS );
		\WP_CLI::success( "Deleted {$deleted} old attempts." );
	}
}
