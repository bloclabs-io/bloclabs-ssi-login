<?php
/**
 * The account an agent token acts as, and how the agent came to it.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

final class AgentAccount {

	/**
	 * @param \WP_User $user      The account the token will act as.
	 * @param bool     $delegated True when the credential's `acts_for` named the account and it
	 *                            opted in; false when the agent's own key is linked to it.
	 */
	public function __construct(
		public readonly \WP_User $user,
		public readonly bool $delegated,
	) {}
}
