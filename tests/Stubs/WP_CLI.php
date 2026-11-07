<?php
/**
 * Unit-test stand-in for WP-CLI: collects what a command printed. The real
 * error() exits the process; this one throws, so a test can assert on it.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_CLI' ) ) {
	final class WP_CLI {
		/** @var list<string> */
		public static array $lines = array();

		public static function add_command( string $name, $command ): void {
			$GLOBALS['bloclabs_ssi_test_cli_commands'][ $name ] = $command;
		}

		public static function log( string $message ): void {
			self::$lines[] = $message;
		}

		public static function success( string $message ): void {
			self::$lines[] = 'Success: ' . $message;
		}

		public static function warning( string $message ): void {
			self::$lines[] = 'Warning: ' . $message;
		}

		public static function error( string $message ): void {
			throw new RuntimeException( 'Error: ' . esc_html( $message ) );
		}

		/**
		 * @param array<string, mixed> $assoc_args
		 */
		public static function confirm( string $message, array $assoc_args = array() ): void {
			self::$lines[] = 'Confirm: ' . $message;
			$accepted      = ! empty( $assoc_args['yes'] );
			if ( ! $accepted && ! empty( $GLOBALS['bloclabs_ssi_test_cli_decline'] ) ) {
				throw new RuntimeException( 'Error: aborted' );
			}
		}
	}
}
