<?php
/**
 * The application token format of ADR 0007 §4 (#90).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Login\AgentToken;
use PHPUnit\Framework\TestCase;

final class AgentTokenTest extends TestCase {

	public function test_a_token_is_the_prefix_and_43_base64url_characters(): void {
		$token = AgentToken::generate();

		$this->assertSame( AgentToken::LENGTH, strlen( $token ) );
		$this->assertStringStartsWith( 'bssi_', $token );
		$this->assertMatchesRegularExpression( '/^bssi_[A-Za-z0-9_-]{43}$/', $token );
		$this->assertTrue( AgentToken::is_token( $token ) );
	}

	public function test_tokens_are_random(): void {
		$seen = array();
		for ( $i = 0; $i < 50; $i++ ) {
			$seen[ AgentToken::generate() ] = true;
		}
		$this->assertCount( 50, $seen );
	}

	public function test_only_our_format_is_ours(): void {
		$this->assertFalse( AgentToken::is_token( '' ) );
		$this->assertFalse( AgentToken::is_token( 'bssi_' ) );
		$this->assertFalse( AgentToken::is_token( 'bssi_' . str_repeat( 'a', 42 ) ), 'too short' );
		$this->assertFalse( AgentToken::is_token( 'bssi_' . str_repeat( 'a', 44 ) ), 'too long' );
		$this->assertFalse( AgentToken::is_token( 'bssi_' . str_repeat( 'a', 42 ) . '=' ), 'no padding' );
		$this->assertFalse( AgentToken::is_token( 'bssi_' . str_repeat( 'a', 42 ) . '+' ), 'base64url, not base64' );
		$this->assertFalse( AgentToken::is_token( 'BSSI_' . str_repeat( 'a', 43 ) ), 'the prefix is lowercase' );
		$this->assertFalse( AgentToken::is_token( 'ghp_' . str_repeat( 'a', 44 ) ), 'another issuer\'s token is left to it' );
		$this->assertFalse( AgentToken::is_token( str_repeat( 'a', 48 ) ), 'an Application Password-sized value is not ours' );
	}

	public function test_the_stored_form_is_the_sha256_of_the_token(): void {
		$token = AgentToken::generate();

		$this->assertSame( hash( 'sha256', $token ), AgentToken::hash( $token ) );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', AgentToken::hash( $token ) );
		$this->assertStringNotContainsString( substr( $token, 5, 10 ), AgentToken::hash( $token ) );
	}
}
