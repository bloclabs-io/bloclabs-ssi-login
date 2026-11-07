<?php
/**
 * Where issued tokens go: the tokens table (ADR 0007 follow-up 1/7).
 *
 * The issuer only ever writes one row, once, after it has consumed the
 * attempt; this is the one method it needs from the repository.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

interface TokenStore {

	/**
	 * Inserts the token's row.
	 *
	 * @return bool False when the row could not be written: no token exists then.
	 */
	public function store( IssuedToken $token ): bool;
}
