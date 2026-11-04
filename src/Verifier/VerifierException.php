<?php
/**
 * The verifier could not be reached or answered something unusable.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

final class VerifierException extends \RuntimeException {

	/**
	 * Code for an answer WordPress cannot use (malformed, incomplete): never retried.
	 */
	public const UNUSABLE = 422;

	public static function unusable( string $message ): self {
		return new self( $message, self::UNUSABLE );
	}

	/**
	 * Worth retrying: unreachable (code 0), not ready yet (409), a timeout or
	 * early reply (408, 425), the bridge's own rate limit (429) or a server
	 * error (5xx). 404 and other client errors are definitive.
	 */
	public function is_transient(): bool {
		$code = $this->getCode();
		return 0 === $code || in_array( $code, array( 408, 409, 425, 429 ), true ) || $code >= 500;
	}
}
