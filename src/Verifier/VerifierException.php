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
	 * Unreachable (code 0), not ready yet (409) or a server error (5xx): worth retrying.
	 */
	public function is_transient(): bool {
		$code = $this->getCode();
		return 0 === $code || 409 === $code || $code >= 500;
	}
}
