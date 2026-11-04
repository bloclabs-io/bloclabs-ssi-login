<?php
/**
 * ClientIp ranges, wallet URL schemes and the subject commitment.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Support\ClientIp;
use BlocLabs\SsiLogin\Verifier\PresentationOffer;
use BlocLabs\SsiLogin\Verifier\PresentationResult;
use BlocLabs\SsiLogin\Verifier\VerifierException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SupportTest extends TestCase {

	public static function ranges(): array {
		return array(
			'v4 in /24'       => array( '172.18.0.7', '172.18.0.0/24', true ),
			'v4 out of /24'   => array( '172.18.1.7', '172.18.0.0/24', false ),
			'v4 /12 edge'     => array( '172.31.255.255', '172.16.0.0/12', true ),
			'v4 exact'        => array( '10.0.0.5', '10.0.0.5', true ),
			'v4 exact miss'   => array( '10.0.0.6', '10.0.0.5', false ),
			'v6 in /64'       => array( '2001:db8::1', '2001:db8::/64', true ),
			'v6 out'          => array( '2001:db9::1', '2001:db8::/64', false ),
			'family mismatch' => array( '10.0.0.1', '::/0', false ),
			'bad prefix'      => array( '10.0.0.1', '10.0.0.0/33', false ),
			'garbage'         => array( 'not-an-ip', '10.0.0.0/8', false ),
		);
	}

	#[DataProvider( 'ranges' )]
	public function test_in_range( string $ip, string $range, bool $expected ): void {
		$this->assertSame( $expected, ClientIp::in_range( $ip, $range ) );
	}

	public function test_wallet_urls(): void {
		$this->assertTrue( PresentationOffer::is_wallet_url( 'openid4vp://?client_id=x509_san_dns:example.com&request_uri=https%3A%2F%2Fv.example%2Fr%2F1' ) );
		$this->assertTrue( PresentationOffer::is_wallet_url( 'https://wallet.example/authorize?request_uri=x' ) );
		$this->assertFalse( PresentationOffer::is_wallet_url( 'javascript:alert(1)' ) );
		$this->assertFalse( PresentationOffer::is_wallet_url( 'data:text/html,hi' ) );
		$this->assertFalse( PresentationOffer::is_wallet_url( 'http://wallet.example/' ) );
	}

	public function test_unusable_offer_is_refused(): void {
		$this->expectException( VerifierException::class );
		PresentationOffer::from_array(
			array(
				'id'         => 'r1',
				'wallet_url' => 'javascript:alert(1)',
			)
		);
	}

	public function test_an_overlong_request_id_is_refused(): void {
		$this->expectException( VerifierException::class );
		PresentationOffer::from_array(
			array(
				'id'         => str_repeat( 'r', PresentationOffer::MAX_REF_LENGTH + 1 ),
				'wallet_url' => 'openid4vp://?client_id=x509_san_dns:example.com&request_uri=https%3A%2F%2Fv.example%2Fr%2F1',
			)
		);
	}

	/**
	 * The bridge's hash is compared with the on-chain one, which the decoder
	 * normalises; a "0x" prefix or upper case must not read as a mismatch (#30).
	 */
	public function test_the_presentation_hash_is_normalised_like_the_on_chain_value(): void {
		$result = PresentationResult::from_array(
			array(
				'subject_id'        => 'did:example:holder',
				'presentation_hash' => '0x' . str_repeat( 'AB', 32 ),
			)
		);

		$this->assertSame( str_repeat( 'ab', 32 ), $result->presentation_hash );
		$this->assertNull( $result->issuer );
		$this->assertSame( array(), $result->claims );
	}

	/**
	 * @return array<string, array{0: array<string, mixed>}>
	 */
	public static function unusable_results(): array {
		return array(
			'empty hash'   => array(
				array(
					'subject_id'        => 'did:example:holder',
					'presentation_hash' => '',
				),
			),
			'short hash'   => array(
				array(
					'subject_id'        => 'did:example:holder',
					'presentation_hash' => 'abc',
				),
			),
			'not hex'      => array(
				array(
					'subject_id'        => 'did:example:holder',
					'presentation_hash' => str_repeat( 'zz', 32 ),
				),
			),
			'missing hash' => array( array( 'subject_id' => 'did:example:holder' ) ),
			'no subject'   => array( array( 'presentation_hash' => str_repeat( 'ab', 32 ) ) ),
		);
	}

	#[DataProvider( 'unusable_results' )]
	public function test_an_unusable_result_fails_the_attempt_rather_than_retrying( array $data ): void {
		try {
			PresentationResult::from_array( $data );
			$this->fail( 'accepted' );
		} catch ( VerifierException $e ) {
			$this->assertFalse( $e->is_transient() );
		}
	}

	public function test_subject_commitment_is_blinded_per_attempt(): void {
		$did      = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
		$blinding = str_repeat( '12', 32 );
		$a        = Attestation::subject_commitment( str_repeat( 'ab', 32 ), $blinding, $did );
		$b        = Attestation::subject_commitment( str_repeat( 'cd', 32 ), $blinding, $did );
		$c        = Attestation::subject_commitment( str_repeat( 'ab', 32 ), str_repeat( '34', 32 ), $did );

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $a );
		$this->assertNotSame( $a, $b, 'the correlation id salts the commitment' );
		$this->assertNotSame( $a, $c, 'the blinding secret, which never reaches the chain, makes a guessed subject untestable' );
		$this->assertSame( $a, Attestation::subject_commitment( str_repeat( 'AB', 32 ), $blinding, $did ), 'correlation id case does not matter' );
		$this->assertSame( hash( 'sha256', str_repeat( 'ab', 32 ) . ':' . $blinding . ':' . $did ), $a, 'the formula the bridge implements too' );
	}
}
