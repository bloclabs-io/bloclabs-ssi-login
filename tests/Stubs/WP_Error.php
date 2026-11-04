<?php
/**
 * Unit-test stand-in for WP_Error, as far as the FireFly client reads it.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_Error' ) ) {
	final class WP_Error {
		public function __construct( private string $message = '' ) {}

		public function get_error_message(): string {
			return $this->message;
		}
	}
}
