<?php
/**
 * What the browser needs to reach a wallet.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

final class PresentationOffer {

	/**
	 * @param string                    $verifier_ref The verifier's id for the request.
	 * @param string                    $wallet_url   The authorization request URL (openid4vp://… or a universal link), shown as a QR code and a same-device link.
	 * @param array<string, mixed>|null $dc_api       A Digital Credentials API request, when the verifier offers one.
	 */
	public function __construct(
		public readonly string $verifier_ref,
		public readonly string $wallet_url,
		public readonly ?array $dc_api = null,
	) {}

	/**
	 * @param array<string, mixed> $data
	 */
	public static function from_array( array $data ): self {
		$ref = isset( $data['id'] ) && is_string( $data['id'] ) ? $data['id'] : '';
		$url = isset( $data['wallet_url'] ) && is_string( $data['wallet_url'] ) ? $data['wallet_url'] : '';

		if ( '' === $ref || ! self::is_wallet_url( $url ) ) {
			throw new VerifierException( 'The verifier returned an unusable presentation request.' );
		}

		return new self( $ref, $url, isset( $data['dc_api'] ) && is_array( $data['dc_api'] ) ? $data['dc_api'] : null );
	}

	/**
	 * Only wallet schemes and HTTPS universal links; never javascript: or data:.
	 *
	 * The scheme is read per RFC 3986 rather than with parse_url(), which
	 * rejects the host-less `openid4vp://?client_id=…` form wallets use.
	 */
	public static function is_wallet_url( string $url ): bool {
		if ( strlen( $url ) > 4096 || 1 !== preg_match( '/^([a-z][a-z0-9+.\-]*):\/\/[^\s<>"]*$/i', $url, $m ) ) {
			return false;
		}
		return in_array( strtolower( $m[1] ), self::wallet_schemes(), true );
	}

	/**
	 * Allowed wallet URL schemes, lower case. The login script receives the same list.
	 *
	 * @return list<string>
	 */
	public static function wallet_schemes(): array {
		$schemes = (array) apply_filters( 'bloclabs_ssi_wallet_url_schemes', array( 'openid4vp', 'https' ) );
		return array_values( array_unique( array_map( static fn ( $s ) => strtolower( (string) $s ), $schemes ) ) );
	}
}
