<?php
/**
 * Decodes an event captured from a real FireFly v1.5.0 node after one call to
 * SsiLoginAttestor.attest(), and checks the commitment a verifier written in
 * another language computed (Python hashlib) against the plugin's own.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\FireFly\ContractEventDecoder;
use PHPUnit\Framework\TestCase;

final class RealFireFlyEventTest extends TestCase {

	public function test_decodes_a_captured_login_attested_event(): void {
		$fixture = json_decode( (string) file_get_contents( dirname( __DIR__ ) . '/fixtures/firefly-login-attested.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local fixture.

		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array( 'firefly_listener_id' => $fixture['listener'] );

		$a = ( new ContractEventDecoder( new Settings() ) )->decode( $fixture['delivery'] );

		$this->assertNotNull( $a );
		$this->assertTrue( $a->is_verified() );
		$this->assertSame( $fixture['correlation'], $a->correlation_id );
		$this->assertSame( $fixture['presentation_hash'], $a->presentation_hash );
		$this->assertSame( $fixture['commitment'], $a->subject_commitment );
		$this->assertSame(
			$a->subject_commitment,
			Attestation::subject_commitment( $a->correlation_id, $fixture['subject'] ),
			'the verifier and WordPress compute the same commitment'
		);
		$this->assertStringStartsWith( '0x', (string) $a->tx_ref );
	}
}
