<?php
/**
 * The bearer header and the tokens row, without WordPress (#91).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Auth\BearerAuthentication;
use BlocLabs\SsiLogin\Auth\ScopeEnforcement;
use BlocLabs\SsiLogin\Auth\TokenRecord;
use BlocLabs\SsiLogin\Login\AgentToken;
use BlocLabs\SsiLogin\Login\IssuedToken;
use BlocLabs\SsiLogin\Login\Scope;
use PHPUnit\Framework\TestCase;

final class BearerAuthenticationTest extends TestCase {

	public function test_the_bearer_value_is_read_from_the_authorization_header_only(): void {
		$token = AgentToken::generate();

		$this->assertSame( $token, BearerAuthentication::bearer( array( 'HTTP_AUTHORIZATION' => 'Bearer ' . $token ) ) );
		$this->assertSame( $token, BearerAuthentication::bearer( array( 'HTTP_AUTHORIZATION' => '  bearer   ' . $token . ' ' ) ), 'the scheme is case-insensitive, whitespace tolerated' );
		$this->assertSame( $token, BearerAuthentication::bearer( array( 'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer ' . $token ) ), 'Apache CGI' );
		$this->assertSame(
			'first',
			BearerAuthentication::bearer(
				array(
					'HTTP_AUTHORIZATION'          => 'Bearer first',
					'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer second',
				)
			)
		);

		$this->assertNull( BearerAuthentication::bearer( array() ) );
		$this->assertNull( BearerAuthentication::bearer( array( 'HTTP_AUTHORIZATION' => 'Basic ' . $token ) ) );
		$this->assertNull( BearerAuthentication::bearer( array( 'HTTP_AUTHORIZATION' => 'Bearer' ) ) );
		$this->assertNull( BearerAuthentication::bearer( array( 'HTTP_AUTHORIZATION' => 'Bearer ' . $token . ' extra' ) ) );
		$this->assertNull( BearerAuthentication::bearer( array( 'HTTP_AUTHORIZATION' => array( 'Bearer ' . $token ) ) ) );
		$this->assertNull(
			BearerAuthentication::bearer(
				array(
					'PHP_AUTH_USER' => 'ada',
					'PHP_AUTH_PW'   => $token,
				)
			),
			'Basic credentials are Application Passwords\' business'
		);
		$this->assertNull( BearerAuthentication::bearer( array( 'HTTP_X_BLOCLABS_TOKEN' => $token ) ) );
	}

	public function test_the_row_the_issuer_writes_is_the_row_the_filter_reads(): void {
		$token  = AgentToken::generate();
		$issued = new IssuedToken( $token, 7, true, str_repeat( 'a', 64 ), 'Deploy bot (Acme)', 'did:web:agents.example', array( 'read', 'content' ), str_repeat( 'c', 64 ), '0xabc', 'evt-1', 1793707200, 1793710800 );
		$row    = $issued->to_row();

		$record = TokenRecord::from_row(
			$row + array(
				'id'           => 3,
				'last_used_at' => null,
				'revoked_at'   => null,
			)
		);

		$this->assertSame( 3, $record->id );
		$this->assertSame( AgentToken::hash( $token ), $record->token_hash );
		$this->assertSame( 7, $record->user_id );
		$this->assertTrue( $record->delegated );
		$this->assertSame( array( 'read', 'content' ), $record->scope );
		$this->assertSame( 'Deploy bot (Acme)', $record->agent_label );
		$this->assertSame( 1793707200, $record->created_at );
		$this->assertSame( 1793710800, $record->expires_at );
		$this->assertNull( $record->last_used_at );
		$this->assertFalse( $record->is_revoked() );
		$this->assertFalse( $record->is_expired( 1793710799 ) );
		$this->assertTrue( $record->is_expired( 1793710800 ) );

		$revoked = TokenRecord::from_row(
			$row + array(
				'id'           => 4,
				'revoked_at'   => '2026-11-03 12:30:00',
				'last_used_at' => '2026-11-03 12:10:00',
			)
		);
		$this->assertTrue( $revoked->is_revoked() );
		$this->assertSame( 1793707800, $revoked->last_used_at );

		$malformed = TokenRecord::from_row(
			array(
				'token_hash' => 'x',
				'user_id'    => '7',
				'scope'      => 'not json',
				'delegated'  => '0',
			)
		);
		$this->assertSame( array(), $malformed->scope, 'an unreadable scope grants nothing' );
		$this->assertFalse( $malformed->delegated );
		$this->assertTrue( $malformed->is_expired(), 'no expiry means expired' );
	}

	public function test_the_self_service_capabilities_are_the_ones_the_adr_names(): void {
		$this->assertSame(
			array( 'edit_user', 'delete_user', 'promote_user', 'create_app_password', 'list_app_passwords', 'read_app_password', 'edit_app_password', 'delete_app_password', 'delete_app_passwords' ),
			ScopeEnforcement::SELF_SERVICE
		);
		foreach ( Scope::built_in() as $capabilities ) {
			$this->assertSame( array(), array_intersect( $capabilities, ScopeEnforcement::SELF_SERVICE ) );
		}
	}
}
