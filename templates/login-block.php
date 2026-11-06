<?php
/**
 * Markup for the SSI login block. Override with the `bloclabs_ssi_login_template` filter.
 *
 * @package BlocLabs\SsiLogin
 */

defined( 'ABSPATH' ) || exit;
?>
<div id="bloclabs-ssi" class="bloclabs-ssi" hidden>
	<p class="bloclabs-ssi__divider"><span><?php esc_html_e( 'or', 'bloclabs-ssi-login' ); ?></span></p>

	<button type="button" class="button button-large bloclabs-ssi__start" data-ssi-start>
		<?php esc_html_e( 'Log in with a digital credential', 'bloclabs-ssi-login' ); ?>
	</button>

	<div class="bloclabs-ssi__panel" data-ssi-panel hidden>
		<p class="bloclabs-ssi__hint" data-ssi-hint><?php esc_html_e( 'Scan with your wallet app, or open it on this device.', 'bloclabs-ssi-login' ); ?></p>
		<div class="bloclabs-ssi__qr" data-ssi-qr role="img" aria-label="<?php esc_attr_e( 'QR code for your wallet', 'bloclabs-ssi-login' ); ?>"></div>
		<p><a class="button bloclabs-ssi__open" data-ssi-open href="#" rel="noopener"><?php esc_html_e( 'Open wallet on this device', 'bloclabs-ssi-login' ); ?></a></p>
		<p class="bloclabs-ssi__status" data-ssi-status role="status" aria-live="polite"></p>
		<button type="button" class="button-link bloclabs-ssi__cancel" data-ssi-cancel><?php esc_html_e( 'Cancel', 'bloclabs-ssi-login' ); ?></button>
	</div>
</div>
