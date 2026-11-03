<?php
/**
 * A FireFly call failed. The code is the HTTP status, or 0 when unreachable.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

final class FireFlyException extends \RuntimeException {

	public function is_not_found(): bool {
		return 404 === $this->getCode();
	}
}
