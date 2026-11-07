<?php
/** @package BlocLabs\SsiLogin */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Session\Attempt;
use PHPUnit\Framework\TestCase;

final class AttemptScopeTest extends TestCase {

	/** @return array<string, mixed> */
	private function row(): array {
		return array(
			'id'             => 1,
			'public_id'      => str_repeat( 'a', 32 ),
			'correlation_id' => str_repeat( 'b', 64 ),
			'binding_hash'   => str_repeat( 'c', 64 ),
			'nonce'          => 'nonce',
			'status'         => 'pending',
			'created_at'     => '2026-01-01 00:00:00',
			'expires_at'     => '2026-01-01 00:03:00',
		);
	}

	public function test_old_rows_remain_browser_logins_without_scope(): void {
		$attempt = Attempt::from_row( $this->row() );
		$this->assertSame( 'browser', $attempt->kind );
		$this->assertSame( 'login', $attempt->purpose );
		$this->assertSame( array(), $attempt->requested_scope );
	}

	public function test_agent_scope_is_a_list_and_malformed_scope_grants_nothing(): void {
		$row         = $this->row();
		$row['kind'] = 'agent';
		foreach ( array( null, '', 'null', 'true', '"content"', '{"scope":"content"}', '["read",1]', 'invalid' ) as $value ) {
			$row['requested_scope'] = $value;
			$this->assertSame( array(), Attempt::from_row( $row )->requested_scope );
		}
		$row['requested_scope'] = '["read","content"]';
		$this->assertSame( 'agent', Attempt::from_row( $row )->kind );
		$this->assertSame( array( 'read', 'content' ), Attempt::from_row( $row )->requested_scope );
	}
}
