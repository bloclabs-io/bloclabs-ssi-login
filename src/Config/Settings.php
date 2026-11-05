<?php
/**
 * Typed access to the plugin settings.
 *
 * Every key can be pinned in wp-config.php as a constant named
 * BLOCLABS_SSI_<KEY> (for example BLOCLABS_SSI_WEBHOOK_SECRET). A constant
 * always wins over the stored option, and secrets should only ever be set
 * that way, so they stay out of the database and its backups.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Config;

final class Settings {

	public const OPTION             = 'bloclabs_ssi_settings';
	public const SUBJECT_KEY_OPTION = 'bloclabs_ssi_subject_key';

	/** Keys that are secrets: never rendered back into a form. */
	public const SECRETS = array( 'firefly_auth_header', 'webhook_secret', 'verifier_auth_header' );

	public const EVENT_MODE_WEBHOOK = 'webhook';
	public const EVENT_MODE_POLL    = 'poll';

	public const LINK_ONLY      = 'link_only';
	public const AUTO_PROVISION = 'auto_provision';

	/** @var array<string, mixed>|null */
	private ?array $stored = null;

	/**
	 * Defaults, which also define the set of valid keys.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults(): array {
		return array(
			'enabled'              => false,
			// FireFly core, as WordPress reaches it (an internal address is best: FireFly's API has no auth of its own).
			'firefly_url'          => 'http://127.0.0.1:5000',
			'firefly_namespace'    => 'default',
			'firefly_auth_header'  => '',
			// The contract listener that watches the attestor contract's LoginAttested event.
			'firefly_listener_id'  => '',
			'attestor_address'     => '',
			'attestation_event'    => 'LoginAttested',
			'event_mode'           => self::EVENT_MODE_WEBHOOK,
			'webhook_secret'       => '',
			'webhook_allowed_ips'  => '',
			// Seconds before a pending attempt in webhook mode starts polling FireFly as a fallback.
			'poll_fallback_after'  => 15,
			'verifier_url'         => 'http://127.0.0.1:8090',
			'verifier_auth_header' => '',
			// A named credential query the verifier knows (DCQL lives in the verifier, not in WordPress).
			'credential_query'     => 'default',
			'attempt_ttl'          => 180,
			// Login attempts one client may open per 10 minutes, whatever became of them.
			// A client is an IPv4 address or an IPv6 /64.
			'max_pending_per_ip'   => 10,
			// Login attempts all clients together may open per 10 minutes: the verifier and the table see no more.
			'max_pending_total'    => 500,
			// $_SERVER key holding the visitor IP behind a trusted proxy, e.g. HTTP_CF_CONNECTING_IP or
			// HTTP_X_FORWARDED_FOR. Empty: REMOTE_ADDR. Only set it when the origin is unreachable except
			// through that proxy; otherwise the header is spoofable.
			'client_ip_header'     => '',
			// Trusted proxies that append their peer to that header: the client is this many entries from
			// the right. The left-most entry is whatever the sender wrote.
			'client_ip_proxies'    => 1,
			'linking_policy'       => self::LINK_ONLY,
			'default_role'         => 'subscriber',
		);
	}

	/**
	 * @return mixed
	 */
	public function get( string $key ) {
		$defaults = self::defaults();
		if ( ! array_key_exists( $key, $defaults ) ) {
			throw new \InvalidArgumentException( esc_html( "Unknown setting: {$key}" ) );
		}

		$constant = self::constant_name( $key );
		if ( defined( $constant ) ) {
			return constant( $constant );
		}

		$this->stored ??= (array) get_option( self::OPTION, array() );
		return $this->stored[ $key ] ?? $defaults[ $key ];
	}

	public function string( string $key ): string {
		return trim( (string) $this->get( $key ) );
	}

	public function int( string $key ): int {
		return (int) $this->get( $key );
	}

	public function bool( string $key ): bool {
		return filter_var( $this->get( $key ), FILTER_VALIDATE_BOOLEAN );
	}

	public function enabled(): bool {
		return $this->bool( 'enabled' );
	}

	public function is_pinned( string $key ): bool {
		return defined( self::constant_name( $key ) );
	}

	public static function constant_name( string $key ): string {
		return 'BLOCLABS_SSI_' . strtoupper( $key );
	}

	/**
	 * Whether the site is served over HTTPS, even when PHP sits behind a TLS
	 * proxy that does not set `HTTPS` (where is_ssl() is false).
	 */
	public function site_is_https(): bool {
		return is_ssl() || 'https' === strtolower( (string) wp_parse_url( home_url(), PHP_URL_SCHEME ) );
	}

	/**
	 * Creates the settings option with autoload off, so values typed into the
	 * settings form are not loaded on every request. A no-op when it exists.
	 */
	public static function ensure_option(): void {
		add_option( self::OPTION, array(), '', false );
	}

	/**
	 * Key for HMAC-ing subject identifiers before they are stored.
	 *
	 * It is the plugin's own key, not a WordPress salt: rotating the salts must
	 * not unlink every credential from its account. Set BLOCLABS_SSI_SUBJECT_KEY
	 * in wp-config.php to keep it out of the database; the stored fallback
	 * protects only against reading the identities table on its own.
	 */
	public function subject_key(): string {
		if ( defined( 'BLOCLABS_SSI_SUBJECT_KEY' ) ) {
			return (string) BLOCLABS_SSI_SUBJECT_KEY;
		}
		return self::ensure_subject_key();
	}

	public static function ensure_subject_key(): string {
		$key = (string) get_option( self::SUBJECT_KEY_OPTION, '' );
		if ( '' === $key ) {
			$key = bin2hex( random_bytes( 32 ) );
			add_option( self::SUBJECT_KEY_OPTION, $key, '', false );
			// Another request may have won the race; read back what was stored.
			$key = (string) get_option( self::SUBJECT_KEY_OPTION, $key );
		}
		return $key;
	}

	/**
	 * Drop the per-request cache after the settings page saves.
	 */
	public function flush(): void {
		$this->stored = null;
	}
}
