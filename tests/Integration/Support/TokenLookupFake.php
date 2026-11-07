<?php
/**
 * Tokens table double for the bearer filter, until follow-up 1/7 lands the real one.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration\Support;

use BlocLabs\SsiLogin\Auth\TokenLookup;
use BlocLabs\SsiLogin\Auth\TokenRecord;
use BlocLabs\SsiLogin\Login\AgentToken;

final class TokenLookupFake implements TokenLookup {

	/** @var array<string, TokenRecord> */
	private array $records = array();

	/** @var list<array{0: TokenRecord, 1: int}> */
	public array $touched = array();

	public int $finds = 0;

	/**
	 * Mints a token for a user and remembers its row.
	 *
	 * @param list<string> $scope
	 * @return string The token, as the agent would hold it.
	 */
	public function mint( int $user_id, array $scope = array( 'read' ), array $overrides = array() ): string {
		$token                                  = AgentToken::generate();
		$now                                    = time();
		$fields                                 = array_merge(
			array(
				'id'           => count( $this->records ) + 1,
				'token_hash'   => AgentToken::hash( $token ),
				'user_id'      => $user_id,
				'delegated'    => false,
				'scope'        => $scope,
				'agent_label'  => 'Deploy bot',
				'created_at'   => $now,
				'expires_at'   => $now + 3600,
				'last_used_at' => null,
				'revoked_at'   => null,
			),
			$overrides
		);
		$this->records[ $fields['token_hash'] ] = new TokenRecord( ...array_values( $fields ) );
		return $token;
	}

	public function find( string $token_hash ): ?TokenRecord {
		++$this->finds;
		return $this->records[ $token_hash ] ?? null;
	}

	public function touch( TokenRecord $token, int $now ): void {
		$this->touched[] = array( $token, $now );
	}
}
