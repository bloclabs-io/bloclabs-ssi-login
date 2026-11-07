<?php
/**
 * Composition root: builds the services once and registers the hooks.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin;

use BlocLabs\SsiLogin\Admin\SettingsPage;
use BlocLabs\SsiLogin\Assets\AssetManager;
use BlocLabs\SsiLogin\Cli\Command;
use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Cron\PurgeExpired;
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\FireFly\AttestationProcessor;
use BlocLabs\SsiLogin\FireFly\ContractEventDecoder;
use BlocLabs\SsiLogin\FireFly\EventDecoder;
use BlocLabs\SsiLogin\FireFly\EventReconciler;
use BlocLabs\SsiLogin\FireFly\FireFlyClient;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Identity\UserResolver;
use BlocLabs\SsiLogin\Login\LoginChecks;
use BlocLabs\SsiLogin\Login\LoginFinalizer;
use BlocLabs\SsiLogin\Login\LoginScreen;
use BlocLabs\SsiLogin\Rest\Routes;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\BrowserBinding;
use BlocLabs\SsiLogin\Verifier\BridgeClient;
use BlocLabs\SsiLogin\Verifier\VerifierClient;

/**
 * One instance per request. Services are built lazily, so a front-end page
 * that never touches login pays only for hook registration.
 */
final class Plugin {

	private static ?self $instance = null;

	private bool $booted = false;

	/** @var array<string, object> */
	private array $services = array();

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	private function __construct() {}

	public function boot(): void {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		if ( ! Schema::maybe_upgrade() ) {
			return;
		}

		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( 'rest_api_init', fn () => ( new Routes( $this ) )->register() );

		( new PurgeExpired( $this->attempts() ) )->register();

		// A deleted user, or one removed from this site, keeps no credential link.
		add_action( 'deleted_user', fn ( $user_id ) => $this->identities()->unlink_user( (int) $user_id ) );
		add_action( 'remove_user_from_blog', array( $this, 'unlink_removed_user' ), 10, 2 );

		if ( $this->settings()->enabled() ) {
			( new LoginScreen( $this->settings(), new AssetManager( $this->settings() ) ) )->register();
		}

		if ( is_admin() ) {
			( new SettingsPage( $this->settings() ) )->register();
			( new \BlocLabs\SsiLogin\Admin\ProfileScreen( $this ) )->register();
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			Command::register( $this );
		}

		/**
		 * Fires after the plugin has registered its hooks.
		 *
		 * @param Plugin $plugin The composition root, for add-ons that need a service.
		 */
		do_action( 'bloclabs_ssi_booted', $this );
	}

	/**
	 * @param int|string $user_id
	 * @param int|string $blog_id
	 */
	public function unlink_removed_user( $user_id, $blog_id ): void {
		if ( get_current_blog_id() === (int) $blog_id ) {
			$this->identities()->unlink_user( (int) $user_id );
			return;
		}
		// Another site: unlink there, and only if switching to it worked.
		if ( is_multisite() && switch_to_blog( (int) $blog_id ) ) {
			$this->identities()->unlink_user( (int) $user_id );
			restore_current_blog();
		}
	}

	public function load_textdomain(): void {
		load_plugin_textdomain( 'bloclabs-ssi-login', false, dirname( plugin_basename( PLUGIN_FILE ) ) . '/languages' );
	}

	public function settings(): Settings {
		return $this->service( Settings::class, static fn () => new Settings() );
	}

	public function attempts(): AttemptRepository {
		return $this->service( AttemptRepository::class, static fn () => new AttemptRepository() );
	}

	public function identities(): IdentityRepository {
		return $this->service( IdentityRepository::class, static fn () => new IdentityRepository() );
	}

	public function binding(): BrowserBinding {
		return $this->service( BrowserBinding::class, fn () => new BrowserBinding( $this->settings() ) );
	}

	public function firefly(): FireFlyClient {
		return $this->service( FireFlyClient::class, fn () => new FireFlyClient( $this->settings() ) );
	}

	/**
	 * The verifier sidecar. Replace it through the `bloclabs_ssi_verifier_client`
	 * filter to talk to a different OpenID4VP verifier.
	 */
	public function verifier(): VerifierClient {
		return $this->service(
			VerifierClient::class,
			function (): VerifierClient {
				$default = new BridgeClient( $this->settings() );
				$client  = apply_filters( 'bloclabs_ssi_verifier_client', $default, $this );
				return $client instanceof VerifierClient ? $client : $default;
			}
		);
	}

	/**
	 * Turns a FireFly event into an attestation. Replace it through the
	 * `bloclabs_ssi_event_decoder` filter when your contract emits a different event.
	 */
	public function decoder(): EventDecoder {
		return $this->service(
			EventDecoder::class,
			function (): EventDecoder {
				$default = new ContractEventDecoder( $this->settings() );
				$decoder = apply_filters( 'bloclabs_ssi_event_decoder', $default, $this );
				return $decoder instanceof EventDecoder ? $decoder : $default;
			}
		);
	}

	public function processor(): AttestationProcessor {
		return $this->service(
			AttestationProcessor::class,
			fn () => new AttestationProcessor( $this->settings(), $this->firefly(), $this->decoder(), $this->attempts() )
		);
	}

	public function reconciler(): EventReconciler {
		return $this->service(
			EventReconciler::class,
			fn () => new EventReconciler( $this->settings(), $this->firefly(), $this->processor(), $this->attempts() )
		);
	}

	/**
	 * The checks a verified attempt passes before it becomes a session or a token.
	 */
	public function checks(): LoginChecks {
		return $this->service( LoginChecks::class, fn () => new LoginChecks( $this->attempts(), $this->verifier() ) );
	}

	public function users(): UserResolver {
		return $this->service( UserResolver::class, fn () => new UserResolver( $this->settings(), $this->identities() ) );
	}

	public function finalizer(): LoginFinalizer {
		return $this->service(
			LoginFinalizer::class,
			fn () => new LoginFinalizer( $this->attempts(), $this->checks(), $this->users(), $this->binding() )
		);
	}

	/**
	 * @template T of object
	 * @param class-string<T> $id
	 * @param callable():T    $factory
	 * @return T
	 */
	private function service( string $id, callable $factory ): object {
		return $this->services[ $id ] ??= $factory();
	}
}
