<?php
/**
 * REST routes under /wp-json/bloclabs-ssi/v1.
 *
 *   POST /initiate          browser  opens an attempt, returns the wallet URL
 *   GET  /status/{attempt}  browser  polls (cookie-bound)
 *   POST /complete          browser  turns a verified attempt into a session
 *   POST /firefly/events    FireFly  webhook doorbell (shared secret)
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Rest;

use BlocLabs\SsiLogin\Plugin;

final class Routes {

	public const NAMESPACE = 'bloclabs-ssi/v1';

	public function __construct( private readonly Plugin $plugin ) {}

	public function register(): void {
		$p = $this->plugin;

		$controllers = array(
			new InitiateController( $p->settings(), $p->attempts(), $p->binding(), $p->verifier() ),
			new StatusController( $p->settings(), $p->attempts(), $p->binding(), $p->reconciler() ),
			new CompleteController( $p->settings(), $p->attempts(), $p->binding(), $p->finalizer() ),
			new WebhookController( $p->settings(), $p->processor() ),
		);

		foreach ( $controllers as $controller ) {
			$controller->register_routes();
		}
	}
}
