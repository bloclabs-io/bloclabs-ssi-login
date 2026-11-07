<?php
/**
 * The application token's format (ADR 0007 §4).
 *
 * `bssi_` and 43 base64url characters: 32 bytes from random_bytes(). The
 * prefix is for secret scanners and log filters; the rest is the secret. The
 * token is opaque, returned once and stored as its SHA-256, so WordPress
 * never parses one and a database dump holds nothing usable.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

final class AgentToken {

	public const PREFIX = 'bssi_';

	/** 5 characters of prefix and 43 of base64url: 256 bits of entropy. */
	public const LENGTH = 48;

	private const PATTERN = '/^bssi_[A-Za-z0-9_-]{43}$/';

	public static function generate(): string {
		return self::PREFIX . rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- base64url of random bytes.
	}

	/**
	 * Whether a bearer value is one of ours. Anything else belongs to whatever
	 * plugin issued it and is left alone.
	 */
	public static function is_token( string $value ): bool {
		return 1 === preg_match( self::PATTERN, $value );
	}

	/**
	 * What the tokens table stores: 64 lowercase hex characters.
	 */
	public static function hash( string $token ): string {
		return hash( 'sha256', $token );
	}
}
