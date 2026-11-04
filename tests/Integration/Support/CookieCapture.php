<?php
/**
 * Capture the actual arguments at PHP's cookie boundary; CLI has no header list.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Session;

/**
 * @param array<string, mixed> $options PHP cookie options.
 */
function setcookie( string $name, string $value, array $options ): bool {
	$GLOBALS['bloclabs_ssi_test_cookies'][] = array( $name, $value, $options );
	return \setcookie( $name, $value, $options );
}
