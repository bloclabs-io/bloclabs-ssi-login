<?php
/**
 * Credential management on the logged-in user's own WordPress profile.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Admin;

use BlocLabs\SsiLogin\Assets\AssetManager;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Rest\BrowserController;
use BlocLabs\SsiLogin\Rest\PageToken;
use BlocLabs\SsiLogin\Verifier\PresentationOffer;

use const BlocLabs\SsiLogin\PLUGIN_DIR;
use const BlocLabs\SsiLogin\PLUGIN_FILE;
use const BlocLabs\SsiLogin\VERSION;

final class ProfileScreen {

	public function __construct( private readonly Plugin $plugin ) {}

	public function register(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	public function enqueue( string $hook ): void {
		if ( 'profile.php' !== $hook || ! $this->plugin->settings()->enabled() || ! current_user_can( 'read' ) ) {
			return;
		}
		$deps = array();
		if ( is_readable( PLUGIN_DIR . '/assets/vendor/qrcode.js' ) ) {
			wp_register_script( AssetManager::QR, plugins_url( 'assets/vendor/qrcode.js', PLUGIN_FILE ), array(), '1.4.4', true );
			$deps[] = AssetManager::QR;
		}
		wp_enqueue_script( 'bloclabs-ssi-profile', plugins_url( 'assets/js/profile.js', PLUGIN_FILE ), $deps, VERSION, true );
		wp_add_inline_script(
			'bloclabs-ssi-profile',
			'window.bloclabsSsiProfile = ' . wp_json_encode(
				array(
					'restBase'    => ( new AssetManager( $this->plugin->settings() ) )->rest_base(),
					'tokenHeader' => BrowserController::TOKEN_HEADER,
					'token'       => PageToken::create(),
					'nonce'       => wp_create_nonce( 'wp_rest' ),
					'schemes'     => PresentationOffer::wallet_schemes(),
					'i18n'        => array(
						'waiting' => __( 'Waiting for your wallet…', 'bloclabs-ssi-login' ),
						'error'   => __( 'The request could not be completed. Please start again.', 'bloclabs-ssi-login' ),
						'confirm' => __( 'Unlink this credential? You will need another way to log in.', 'bloclabs-ssi-login' ),
					),
				)
			) . ';',
			'before'
		);
	}

	public function render( \WP_User $user ): void {
		if ( ! $this->plugin->settings()->enabled() || get_current_user_id() !== $user->ID || ! current_user_can( 'read' ) ) {
			return;
		}
		?>
		<h2><?php esc_html_e( 'Digital credentials', 'bloclabs-ssi-login' ); ?></h2>
		<div id="bloclabs-ssi-profile" hidden>
			<p><?php esc_html_e( 'Link a credential from your wallet to log in to this account. Keep another way to log in before unlinking.', 'bloclabs-ssi-login' ); ?></p>
			<ul>
				<?php foreach ( $this->plugin->identities()->for_user( $user->ID ) as $identity ) : ?>
					<li>
						<?php echo esc_html( (string) $identity['subject_label'] ); ?>
						<button type="button" class="button" data-ssi-unlink="<?php echo esc_attr( (string) $identity['id'] ); ?>"><?php esc_html_e( 'Unlink', 'bloclabs-ssi-login' ); ?></button>
					</li>
				<?php endforeach; ?>
			</ul>
			<button type="button" class="button" data-ssi-start><?php esc_html_e( 'Link a credential', 'bloclabs-ssi-login' ); ?></button>
			<div data-ssi-panel hidden>
				<p><?php esc_html_e( 'Scan with your wallet app, or open it on this device.', 'bloclabs-ssi-login' ); ?></p>
				<div data-ssi-qr role="img" aria-label="<?php esc_attr_e( 'QR code for your wallet', 'bloclabs-ssi-login' ); ?>"></div>
				<p><a class="button" data-ssi-open hidden rel="noopener"><?php esc_html_e( 'Open wallet on this device', 'bloclabs-ssi-login' ); ?></a></p>
				<button type="button" class="button" data-ssi-cancel><?php esc_html_e( 'Cancel', 'bloclabs-ssi-login' ); ?></button>
			</div>
			<p data-ssi-status role="status" aria-live="polite"></p>
		</div>
		<?php
	}
}
