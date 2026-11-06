<?php
/**
 * wp bloclabs-ssi <status|subscribe|purge|links>
 *
 * phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter -- WP-CLI passes ($args, $assoc_args) to every subcommand.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Cli;

use BlocLabs\SsiLogin\Admin\UserLinksScreen;
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

	/**
	 * Lists or unlinks credential links on this site.
	 *
	 * The subject identifier and the subject hash are never printed. Each row is
	 * the account, the opaque label, the issuer and the last-used time.
	 *
	 * Limit `list` with `--login`. WP-CLI keeps `--user` as its global option
	 * (the account that runs the command), so this command does not declare it.
	 * On multisite the command sees the site selected with WP-CLI's `--url`.
	 *
	 * ## OPTIONS
	 *
	 * <command>
	 * : `list` or `unlink`.
	 *
	 * [<user>]
	 * : For `unlink`, the account (ID, login or email). For `list`, an optional
	 *   account to show. `--login` wins when both are given.
	 *
	 * [--login=<user>]
	 * : With `list`, show one account: a user ID, login or email.
	 *
	 * [--yes]
	 * : With `unlink`, skip the confirmation.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bloclabs-ssi links list
	 *     wp bloclabs-ssi links list --login=ada
	 *     wp bloclabs-ssi links unlink ada
	 *
	 * @param list<string>         $args
	 * @param array<string, mixed> $assoc
	 */
	public function links( array $args, array $assoc ): void {
		$this->assert_can_manage_links();
		$command = isset( $args[0] ) ? (string) $args[0] : '';
		if ( 'list' === $command ) {
			$this->list_links( $args, $assoc );
			return;
		}
		if ( 'unlink' === $command ) {
			$this->unlink_links( $args, $assoc );
			return;
		}
		\WP_CLI::error( 'Usage: wp bloclabs-ssi links list [--login=<user>] | wp bloclabs-ssi links unlink <user>' );
	}

	/**
	 * One listing row. Tabs and line breaks in a cell are flattened so a value
	 * cannot invent an extra column.
	 */
	public static function format_link( string $account, string $label, string $issuer, string $last_used ): string {
		$label  = '' !== $label ? $label : '-';
		$issuer = '' !== $issuer ? $issuer : '-';
		$last   = '' !== $last_used ? $last_used : 'never';
		return self::cell( $account ) . "\t" . self::cell( $label ) . "\t" . self::cell( $issuer ) . "\t" . self::cell( $last );
	}

	/**
	 * @param list<string>         $args
	 * @param array<string, mixed> $assoc
	 */
	private function list_links( array $args, array $assoc ): void {
		$user_id = null;
		$who     = $this->list_filter( $args, $assoc );
		if ( '' !== $who ) {
			$user_id = $this->require_user( $who )->ID;
		}

		$links = $this->plugin->identities()->links_for( $user_id );
		if ( array() === $links ) {
			\WP_CLI::log( 'No linked credentials.' );
			return;
		}

		\WP_CLI::log( "account\tcredential\tissuer\tlast_used" );
		foreach ( $links as $link ) {
			$account = get_userdata( $link['user_id'] );
			$login   = $account instanceof \WP_User ? $account->user_login : '#' . $link['user_id'];
			\WP_CLI::log( self::format_link( $login, $link['subject_label'], $link['issuer'], $link['last_login_at'] ) );
		}
	}

	/**
	 * @param list<string>         $args
	 * @param array<string, mixed> $assoc
	 */
	private function unlink_links( array $args, array $assoc ): void {
		$who = isset( $args[1] ) ? trim( (string) $args[1] ) : '';
		if ( '' === $who ) {
			\WP_CLI::error( 'Usage: wp bloclabs-ssi links unlink <user>' );
		}
		$user  = $this->require_user( $who );
		$links = $this->plugin->identities()->links_for( $user->ID );
		if ( array() === $links ) {
			\WP_CLI::warning( sprintf( 'No linked credential for %s.', $user->user_login ) );
			return;
		}

		\WP_CLI::confirm(
			sprintf(
				/* translators: 1: number of credentials, 2: WordPress username. */
				_n( 'Unlink %1$d credential from %2$s?', 'Unlink %1$d credentials from %2$s?', count( $links ), 'bloclabs-ssi-login' ),
				count( $links ),
				$user->user_login
			),
			$assoc
		);
		$this->plugin->identities()->unlink_user( $user->ID );
		\WP_CLI::success(
			sprintf(
				/* translators: 1: number of credentials, 2: WordPress username. */
				_n( 'Unlinked %1$d credential from %2$s.', 'Unlinked %1$d credentials from %2$s.', count( $links ), 'bloclabs-ssi-login' ),
				count( $links ),
				$user->user_login
			)
		);
	}

	/**
	 * @param list<string>         $args
	 * @param array<string, mixed> $assoc
	 */
	private function list_filter( array $args, array $assoc ): string {
		if ( isset( $assoc['login'] ) && is_scalar( $assoc['login'] ) ) {
			return trim( (string) $assoc['login'] );
		}
		return isset( $args[1] ) ? trim( (string) $args[1] ) : '';
	}

	private function assert_can_manage_links(): void {
		if ( UserLinksScreen::can_manage() ) {
			return;
		}
		$message = is_multisite()
			? 'A network administrator has to run this (manage_network_users). Use WP-CLI --user to choose that account.'
			: 'An account with edit_users has to run this. Use WP-CLI --user to choose that account.';
		\WP_CLI::error( $message );
	}

	private function require_user( string $who ): \WP_User {
		if ( '' === $who ) {
			\WP_CLI::error( 'Give a user ID, login or email.' );
		}
		if ( ctype_digit( $who ) ) {
			$user = get_user_by( 'id', (int) $who );
		} elseif ( is_email( $who ) ) {
			$user = get_user_by( 'email', $who );
		} else {
			$user = get_user_by( 'login', $who );
		}
		if ( ! $user instanceof \WP_User ) {
			\WP_CLI::error( 'No such user.' );
		}
		return $user;
	}

	private static function cell( string $value ): string {
		return str_replace( array( "\t", "\r", "\n" ), ' ', $value );
	}
}
