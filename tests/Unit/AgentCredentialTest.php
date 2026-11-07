<?php
/**
 * Reading the agent credential's claims (ADR 0007 §1) and the credential's expiry (#90).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Identity\AgentCredential;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Verifier\PresentationResult;
use BlocLabs\SsiLogin\Verifier\VerifierException;
use PHPUnit\Framework\TestCase;

final class AgentCredentialTest extends TestCase {

	private const AGENT = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

	private const PRINCIPAL = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

	/**
	 * @param array<string, mixed> $claims
	 */
	private static function presented( array $claims ): PresentationResult {
		return new PresentationResult( self::AGENT, 'did:web:issuer.example', str_repeat( 'ab', 32 ), $claims );
	}

	public function test_acts_for_is_the_principals_subject_id_or_nothing(): void {
		$this->assertSame( self::PRINCIPAL, AgentCredential::acts_for( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ) );
		$this->assertSame( self::PRINCIPAL, AgentCredential::acts_for( self::presented( array( 'acts_for' => '  ' . self::PRINCIPAL . "\n" ) ) ) );
		$this->assertNull( AgentCredential::acts_for( self::presented( array() ) ) );
		$this->assertNull( AgentCredential::acts_for( self::presented( array( 'acts_for' => '' ) ) ) );
		$this->assertNull( AgentCredential::acts_for( self::presented( array( 'acts_for' => '   ' ) ) ) );
		$this->assertNull( AgentCredential::acts_for( self::presented( array( 'acts_for' => array( self::PRINCIPAL ) ) ) ), 'not a string: names nobody' );
		$this->assertNull( AgentCredential::acts_for( self::presented( array( 'acts_for' => 7 ) ) ) );
	}

	public function test_scope_is_absent_a_list_or_empty_but_never_widened_by_a_malformed_claim(): void {
		$this->assertNull( AgentCredential::scope( self::presented( array() ) ), 'no claim: the credential adds no limit' );
		$this->assertSame( array( 'read' ), AgentCredential::scope( self::presented( array( 'scope' => array( 'read' ) ) ) ) );
		$this->assertSame( array( 'read', 'content' ), AgentCredential::scope( self::presented( array( 'scope' => 'read content' ) ) ) );
		$this->assertSame( array(), AgentCredential::scope( self::presented( array( 'scope' => array() ) ) ), 'an empty list allows nothing' );
		$this->assertSame( array(), AgentCredential::scope( self::presented( array( 'scope' => null ) ) ), 'present but null allows nothing' );
		$this->assertSame( array(), AgentCredential::scope( self::presented( array( 'scope' => 42 ) ) ), 'malformed allows nothing' );
		$this->assertSame( array( 'read' ), AgentCredential::scope( self::presented( array( 'scope' => array( 'read', 'Not Valid', 3 ) ) ) ) );
	}

	public function test_the_label_is_the_agent_name_and_operator_sanitised_or_the_keyed_fingerprint(): void {
		$this->assertSame(
			'Deploy bot (Acme)',
			AgentCredential::label(
				self::presented(
					array(
						'agent' => array(
							'name'     => 'Deploy bot',
							'operator' => 'Acme',
						),
					)
				),
				'key'
			)
		);
		$this->assertSame( 'Deploy bot', AgentCredential::label( self::presented( array( 'agent' => array( 'name' => '<b>Deploy</b> bot ' ) ) ), 'key' ), 'markup stripped' );
		$this->assertSame(
			'Acme',
			AgentCredential::label(
				self::presented(
					array(
						'agent' => array(
							'operator' => 'Acme',
							'name'     => 7,
						),
					)
				),
				'key'
			)
		);

		$fallback = AgentCredential::label( self::presented( array() ), 'key' );
		$this->assertSame( IdentityRepository::label( self::AGENT, 'key' ), $fallback );
		$this->assertMatchesRegularExpression( '/^credential #[0-9a-f]{8}$/', $fallback );
		$this->assertSame( $fallback, AgentCredential::label( self::presented( array( 'agent' => 'Deploy bot' ) ), 'key' ), 'a non-object agent claim is ignored' );
		$this->assertSame( $fallback, AgentCredential::label( self::presented( array( 'agent' => array( 'name' => '<script></script>' ) ) ), 'key' ), 'a name that sanitises to nothing is no name' );

		$long = AgentCredential::label( self::presented( array( 'agent' => array( 'name' => str_repeat( 'n', 200 ) ) ) ), 'key' );
		$this->assertSame( 191, mb_strlen( $long ), 'cut to the column' );
	}

	public function test_the_result_carries_the_credentials_expiry_when_the_bridge_reports_it(): void {
		$base = array(
			'subject_id'        => self::AGENT,
			'presentation_hash' => str_repeat( 'ab', 32 ),
		);

		$this->assertNull( PresentationResult::from_array( $base )->expires_at, 'absent: the TTL alone applies' );
		$this->assertNull( PresentationResult::from_array( $base + array( 'expires_at' => null ) )->expires_at );
		$this->assertSame( 1793707200, PresentationResult::from_array( $base + array( 'expires_at' => '2026-11-03T12:00:00Z' ) )->expires_at, 'RFC 3339, as the request sends it' );
		$this->assertSame( 1793707200, PresentationResult::from_array( $base + array( 'expires_at' => '2026-11-03T12:00:00.250Z' ) )->expires_at, 'with fractional seconds' );
		$this->assertSame( 1793700000, PresentationResult::from_array( $base + array( 'expires_at' => '2026-11-03T12:00:00+02:00' ) )->expires_at, 'an offset is honoured' );
		$this->assertSame( 1793707200, PresentationResult::from_array( $base + array( 'expires_at' => 1793707200 ) )->expires_at, 'Unix seconds' );
	}

	/**
	 * @return list<array{0: mixed}>
	 */
	public static function unreadable_expiries(): array {
		return array(
			array( 'tomorrow' ),
			array( '2026-11-03 12:00:00' ),
			array( '' ),
			array( 0 ),
			array( -5 ),
			array( 1793707200.5 ),
			array( array( '2026-11-03T12:00:00Z' ) ),
			array( true ),
		);
	}

	/**
	 * An expiry WordPress cannot read is not ignored: ignoring it would let a token outlive the credential.
	 *
	 * @dataProvider unreadable_expiries
	 * @param mixed $expires_at
	 */
	public function test_an_unreadable_expiry_makes_the_result_unusable( $expires_at ): void {
		$this->expectException( VerifierException::class );
		$this->expectExceptionCode( VerifierException::UNUSABLE );

		PresentationResult::from_array(
			array(
				'subject_id'        => self::AGENT,
				'presentation_hash' => str_repeat( 'ab', 32 ),
				'expires_at'        => $expires_at,
			)
		);
	}
}
