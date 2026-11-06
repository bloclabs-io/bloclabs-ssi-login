<?php
/**
 * Link completion policy without WordPress or a database.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

// Namespace-local WordPress doubles, isolated from the integration suite.
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
function is_user_logged_in(): bool {
	return get_current_user_id() > 0;
}
function get_current_user_id(): int {
	return $GLOBALS['bloclabs_ssi_link_test_user'] ?? 0;
}
function current_user_can( string $capability ): bool { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
	return true;
}
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
