<?php
/**
 * What the bearer filter needs from the tokens table (ADR 0007 follow-up 1/7):
 * the row behind a presented token, and a note of its use.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Auth;

interface TokenLookup {

	/**
	 * The row whose `token_hash` is this, revoked or expired rows included: the
	 * filter tells those apart from an unknown token for the refusal action.
	 */
	public function find( string $token_hash ): ?TokenRecord;

	/**
	 * Records that the token was used now (`last_used_at`).
	 */
	public function touch( TokenRecord $token, int $now ): void;
}
