<?php
/**
 * Client address helpers: rate-limit keys and the webhook allowlist.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Support;

use BlocLabs\SsiLogin\Config\Settings;

final class ClientIp {

	/**
	 * The visitor's address: REMOTE_ADDR, or the configured proxy header.
	 */
	public static function address( Settings $settings ): ?string {
		$key = $settings->string( 'client_ip_header' );
		$raw = '' !== $key && isset( $_SERVER[ $key ] ) ? (string) $_SERVER[ $key ] : (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated as an IP below.
		// A forwarded-for list: the left-most entry is the client.
		$ip = trim( explode( ',', $raw )[0] );

		/**
		 * Override the visitor IP (for proxies the header setting cannot describe).
		 *
		 * @param string|null $ip
		 */
		$ip = apply_filters( 'bloclabs_ssi_client_ip', false !== filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : null );
		return is_string( $ip ) && '' !== $ip ? $ip : null;
	}

	/**
	 * Keyed hash of the visitor IP: rate limiting without storing addresses.
	 */
	public static function hash( Settings $settings ): ?string {
		$ip = self::address( $settings );
		return null === $ip ? null : hash_hmac( 'sha256', $ip, $settings->subject_key() );
	}

	/**
	 * For the webhook: the direct peer only, never a forwarded header.
	 *
	 * @param string $allowlist Comma or whitespace separated IPs and CIDR ranges.
	 */
	public static function remote_addr_in( string $allowlist ): bool {
		$ip     = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared, never output.
		$ranges = preg_split( '/[\s,]+/', $allowlist, -1, PREG_SPLIT_NO_EMPTY );
		foreach ( is_array( $ranges ) ? $ranges : array() as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * IPv4 or IPv6 address in a CIDR range (or equal to a single address).
	 */
	public static function in_range( string $ip, string $range ): bool {
		list( $subnet, $bits ) = array_pad( explode( '/', $range, 2 ), 2, null );

		$ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- invalid input returns false.
		$subnet_bin = @inet_pton( (string) $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$max  = strlen( $ip_bin ) * 8;
		$bits = null === $bits ? $max : (int) $bits;
		if ( $bits < 0 || $bits > $max ) {
			return false;
		}

		$bytes = intdiv( $bits, 8 );
		if ( substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = chr( ( 0xff << ( 8 - $rest ) ) & 0xff );
		return ( $ip_bin[ $bytes ] & $mask ) === ( $subnet_bin[ $bytes ] & $mask );
	}
}
