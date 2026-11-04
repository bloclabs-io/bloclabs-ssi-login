<?php
/**
 * Settings → SSI Login.
 *
 * Values pinned in wp-config.php are shown read-only. Secrets are never
 * printed back: an empty secret field keeps the stored value.
 *
 * On multisite only a network administrator may view or save the page:
 * these settings decide which hosts WordPress talks to and which accounts
 * it creates, which a site administrator must not control.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Admin;

use BlocLabs\SsiLogin\Config\Settings;

final class SettingsPage {

	private const PAGE = 'bloclabs-ssi-login';

	public function __construct( private readonly Settings $settings ) {}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		// options.php checks manage_options on its own; on multisite the save needs the network capability too.
		add_filter( 'option_page_capability_' . self::PAGE, static fn () => self::capability() );
	}

	/**
	 * Who may view and save the settings.
	 *
	 * On multisite every site administrator holds manage_options, but the
	 * verifier and FireFly URLs, the secrets, the listener id, the event mode,
	 * the linking policy and the client IP header are trust roots: with them a
	 * site administrator could point WordPress at servers they run and have it
	 * create accounts network-wide. So there the page needs manage_network_options.
	 */
	public static function capability(): string {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	public function add_page(): void {
		add_options_page(
			__( 'SSI Login', 'bloclabs-ssi-login' ),
			__( 'SSI Login', 'bloclabs-ssi-login' ),
			self::capability(),
			self::PAGE,
			array( $this, 'render' )
		);
	}

	/**
	 * Field definitions: key => [label, type, section, help].
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3?: string}>
	 */
	private function fields(): array {
		return array(
			'enabled'              => array( __( 'Enable credential login', 'bloclabs-ssi-login' ), 'checkbox', 'general' ),
			'linking_policy'       => array( __( 'Unknown credentials', 'bloclabs-ssi-login' ), 'policy', 'general', __( '"Link only" lets only linked credentials log in. "Create account" registers new users.', 'bloclabs-ssi-login' ) ),
			'default_role'         => array( __( 'Role for new accounts', 'bloclabs-ssi-login' ), 'text', 'general', __( 'Roles that can manage options or users are never granted; subscriber is used instead.', 'bloclabs-ssi-login' ) ),
			'attempt_ttl'          => array( __( 'Request lifetime (seconds)', 'bloclabs-ssi-login' ), 'number', 'general' ),
			'client_ip_header'     => array( __( 'Client IP header', 'bloclabs-ssi-login' ), 'text', 'general', __( 'e.g. HTTP_CF_CONNECTING_IP. Leave empty unless the site is reachable only through that proxy.', 'bloclabs-ssi-login' ) ),
			'verifier_url'         => array( __( 'Verifier bridge URL', 'bloclabs-ssi-login' ), 'url', 'verifier' ),
			'verifier_auth_header' => array( __( 'Verifier Authorization header', 'bloclabs-ssi-login' ), 'secret', 'verifier', __( 'Required: credential login stays off without it. Prefer BLOCLABS_SSI_VERIFIER_AUTH_HEADER in wp-config.php.', 'bloclabs-ssi-login' ) ),
			'credential_query'     => array( __( 'Credential query name', 'bloclabs-ssi-login' ), 'text', 'verifier', __( 'A DCQL query defined in the verifier.', 'bloclabs-ssi-login' ) ),
			'firefly_url'          => array( __( 'FireFly core URL', 'bloclabs-ssi-login' ), 'url', 'firefly', __( 'A private address. FireFly core has no authentication of its own.', 'bloclabs-ssi-login' ) ),
			'firefly_namespace'    => array( __( 'Namespace', 'bloclabs-ssi-login' ), 'text', 'firefly' ),
			'firefly_auth_header'  => array( __( 'FireFly Authorization header', 'bloclabs-ssi-login' ), 'secret', 'firefly', __( 'Only when an authenticating proxy fronts FireFly.', 'bloclabs-ssi-login' ) ),
			'firefly_listener_id'  => array( __( 'Contract listener ID', 'bloclabs-ssi-login' ), 'text', 'firefly' ),
			'event_mode'           => array( __( 'Event delivery', 'bloclabs-ssi-login' ), 'mode', 'firefly' ),
			'webhook_secret'       => array( __( 'Webhook secret', 'bloclabs-ssi-login' ), 'secret', 'firefly', __( 'At least 32 characters. Prefer BLOCLABS_SSI_WEBHOOK_SECRET in wp-config.php.', 'bloclabs-ssi-login' ) ),
			'webhook_allowed_ips'  => array( __( 'Webhook source IPs', 'bloclabs-ssi-login' ), 'text', 'firefly', __( 'Optional. IPs or CIDR ranges, comma separated.', 'bloclabs-ssi-login' ) ),
		);
	}

	public function register_settings(): void {
		register_setting(
			self::PAGE,
			Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
				'show_in_rest'      => false,
				'default'           => array(),
			)
		);

		$sections = array(
			'general'  => __( 'Login', 'bloclabs-ssi-login' ),
			'verifier' => __( 'Verifier (OpenID4VP)', 'bloclabs-ssi-login' ),
			'firefly'  => __( 'Hyperledger FireFly', 'bloclabs-ssi-login' ),
		);
		foreach ( $sections as $id => $title ) {
			add_settings_section( $id, $title, '__return_null', self::PAGE );
		}

		foreach ( $this->fields() as $key => $field ) {
			add_settings_field(
				$key,
				esc_html( $field[0] ),
				array( $this, 'render_field' ),
				self::PAGE,
				$field[2],
				array(
					'key'       => $key,
					'type'      => $field[1],
					'help'      => $field[3] ?? '',
					'label_for' => 'bloclabs-ssi-' . $key,
				)
			);
		}
	}

	/**
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function sanitize( $input ): array {
		$input  = is_array( $input ) ? wp_unslash( $input ) : array();
		$stored = (array) get_option( Settings::OPTION, array() );
		// Start from what is stored (known keys only), so settings this form does not show survive a save.
		$out = array_intersect_key( $stored, Settings::defaults() );

		foreach ( $this->fields() as $key => $field ) {
			if ( $this->settings->is_pinned( $key ) ) {
				continue;
			}
			$value = $input[ $key ] ?? null;
			switch ( $field[1] ) {
				case 'checkbox':
					$out[ $key ] = ! empty( $value );
					break;
				case 'number':
					$out[ $key ] = max( 60, min( 600, absint( $value ) ) );
					break;
				case 'url':
					$out[ $key ] = esc_url_raw( (string) $value, array( 'http', 'https' ) );
					break;
				case 'secret':
					$value       = trim( (string) $value );
					$out[ $key ] = '' === $value ? ( $stored[ $key ] ?? '' ) : $value;
					break;
				case 'policy':
					$out[ $key ] = Settings::AUTO_PROVISION === $value ? Settings::AUTO_PROVISION : Settings::LINK_ONLY;
					break;
				case 'mode':
					$out[ $key ] = Settings::EVENT_MODE_POLL === $value ? Settings::EVENT_MODE_POLL : Settings::EVENT_MODE_WEBHOOK;
					break;
				default:
					$out[ $key ] = sanitize_text_field( (string) $value );
			}
		}

		$this->settings->flush();
		return $out;
	}

	/**
	 * @param array{key: string, type: string, help: string, label_for: string} $args
	 */
	public function render_field( array $args ): void {
		$key   = $args['key'];
		$id    = $args['label_for'];
		$name  = Settings::OPTION . '[' . $key . ']';
		$value = $this->settings->get( $key );

		if ( $this->settings->is_pinned( $key ) ) {
			printf(
				'<code>%s</code> <span class="description">%s</span>',
				esc_html( in_array( $key, Settings::SECRETS, true ) ? '••••••••' : (string) wp_json_encode( $value ) ),
				/* translators: %s: constant name */
				esc_html( sprintf( __( 'Set by %s in wp-config.php.', 'bloclabs-ssi-login' ), Settings::constant_name( $key ) ) )
			);
			return;
		}

		switch ( $args['type'] ) {
			case 'checkbox':
				printf( '<input type="checkbox" id="%s" name="%s" value="1" %s />', esc_attr( $id ), esc_attr( $name ), checked( (bool) $value, true, false ) );
				break;
			case 'secret':
				printf(
					'<input type="password" class="regular-text" id="%s" name="%s" value="" autocomplete="new-password" placeholder="%s" />',
					esc_attr( $id ),
					esc_attr( $name ),
					esc_attr( '' !== (string) $value ? __( 'Stored. Type to replace.', 'bloclabs-ssi-login' ) : '' )
				);
				break;
			case 'policy':
			case 'mode':
				$options = 'policy' === $args['type']
					? array(
						Settings::LINK_ONLY      => __( 'Link only', 'bloclabs-ssi-login' ),
						Settings::AUTO_PROVISION => __( 'Create account', 'bloclabs-ssi-login' ),
					)
					: array(
						Settings::EVENT_MODE_WEBHOOK => __( 'Webhook (FireFly pushes), with polling fallback', 'bloclabs-ssi-login' ),
						Settings::EVENT_MODE_POLL    => __( 'Polling only (FireFly cannot reach WordPress)', 'bloclabs-ssi-login' ),
					);
				printf( '<select id="%s" name="%s">', esc_attr( $id ), esc_attr( $name ) );
				foreach ( $options as $option => $label ) {
					printf( '<option value="%s" %s>%s</option>', esc_attr( $option ), selected( $value, $option, false ), esc_html( $label ) );
				}
				echo '</select>';
				break;
			default:
				printf(
					'<input type="%s" class="regular-text" id="%s" name="%s" value="%s" />',
					esc_attr( 'number' === $args['type'] ? 'number' : 'text' ),
					esc_attr( $id ),
					esc_attr( $name ),
					esc_attr( (string) $value )
				);
		}

		if ( '' !== $args['help'] ) {
			printf( '<p class="description">%s</p>', esc_html( $args['help'] ) );
		}
	}

	public function render(): void {
		if ( ! current_user_can( self::capability() ) ) {
			return;
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'SSI Login', 'bloclabs-ssi-login' ) . '</h1>';
		printf(
			'<p>%s <code>%s</code></p>',
			esc_html__( 'FireFly webhook URL:', 'bloclabs-ssi-login' ),
			esc_html( rest_url( 'bloclabs-ssi/v1/firefly/events' ) )
		);
		echo '<form method="post" action="options.php">';
		settings_fields( self::PAGE );
		do_settings_sections( self::PAGE );
		submit_button();
		echo '</form></div>';
	}
}
