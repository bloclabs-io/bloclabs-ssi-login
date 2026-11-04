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
	 *
	 * A missing header means the request did not come through the proxy, so
	 * REMOTE_ADDR is the client. A header that cannot name the client (fewer
	 * entries than trusted proxies, or not an address) yields null, and the
	 * caller refuses the request rather than rate-limit it on a guess.
	 */
	public static function address( Settings $settings ): ?string {
		$key = $settings->string( 'client_ip_header' );
		$raw = (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated as an IP below.
		$ip  = false !== filter_var( $raw, FILTER_VALIDATE_IP ) ? $raw : null;
		if ( '' !== $key && isset( $_SERVER[ $key ] ) ) {
			$ip = self::forwarded( (string) $_SERVER[ $key ], $settings->int( 'client_ip_proxies' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated in forwarded().
		}

		/**
		 * Override the visitor IP (for proxies the header settings cannot describe).
		 *
		 * @param string|null $ip
		 */
		$ip = apply_filters( 'bloclabs_ssi_client_ip', $ip );
		return is_string( $ip ) && '' !== $ip ? $ip : null;
	}

	/**
	 * The client entry of a forwarded-for header.
	 *
	 * Every proxy appends the address it saw, so the left-most entries are
	 * whatever the sender wrote and only the last $proxies entries can be
	 * trusted: the client is $proxies entries from the right. A single-valued
	 * header (CF-Connecting-IP, X-Real-IP) is the one-proxy case.
	 *
	 * @param int $proxies Trusted proxies that append to the header; at least one.
	 */
	public static function forwarded( string $header, int $proxies ): ?string {
		$entries = array_map( 'trim', explode( ',', $header ) );
		$index   = count( $entries ) - max( 1, $proxies );
		if ( $index < 0 ) {
			return null;
		}
		$ip = $entries[ $index ];
		return false !== filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : null;
	}

	/**
	 * Keyed hash of the client, for rate limiting without storing addresses.
	 */
	public static function hash( Settings $settings ): ?string {
		$ip = self::address( $settings );
		return null === $ip ? null : hash_hmac( 'sha256', self::bucket( $ip ), $settings->subject_key() );
	}

	/**
	 * What the rate limit counts as one client: an IPv4 address, or an IPv6
	 * /64, the prefix one subscriber or server holds and can rotate addresses
	 * within. An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is its IPv4 address.
	 */
	public static function bucket( string $ip ): string {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- invalid input returns false.
		if ( false === $bin ) {
			return $ip;
		}
		if ( 16 === strlen( $bin ) ) {
			if ( str_starts_with( $bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff" ) ) {
				$bin = substr( $bin, 12 );
			} else {
				return inet_ntop( substr( $bin, 0, 8 ) . str_repeat( "\0", 8 ) ) . '/64';
			}
		}
		return (string) inet_ntop( $bin );
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
