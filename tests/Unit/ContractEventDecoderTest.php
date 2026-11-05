<?php
/**
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\FireFly\ContractEventDecoder;
use PHPUnit\Framework\TestCase;

final class ContractEventDecoderTest extends TestCase {

	private const LISTENER = '6f4c2a1e-0d7b-4c55-9a51-3f2d1c0b9e88';

	protected function setUp(): void {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array(
			'firefly_listener_id' => self::LISTENER,
			'attestor_address'    => '0x' . str_repeat( '12', 20 ),
		);
	}

	/**
	 * A delivery as FireFly v1.5 sends it: the enriched event with blockchainEvent embedded.
	 */
	public static function delivery( array $overrides = array(), array $output = array() ): array {
		$event = array(
			'id'              => 'e1bf9817-a9d5-41a0-9b76-48d4d9767db4',
			'sequence'        => 300,
			'type'            => 'blockchain_event_received',
			'namespace'       => 'default',
			'reference'       => '17bce73a-e58b-4ea1-b167-12a5df0dcd05',
			'blockchainEvent' => array(
				'id'       => '17bce73a-e58b-4ea1-b167-12a5df0dcd05',
				'source'   => 'ethereum',
				'name'     => 'LoginAttested',
				'listener' => self::LISTENER,
				'output'   => $output + array(
					'correlationId'     => '0x' . str_repeat( 'ab', 32 ),
					'result'            => '1',
					'subjectCommitment' => '0x' . str_repeat( 'cd', 32 ),
					'presentationHash'  => '0x' . str_repeat( 'EF', 32 ),
					'verifier'          => '0x598cf3c9e9ab6fd77b342f91cb239c258a394e0c',
				),
				'info'     => array(
					'address'         => '0x' . str_repeat( '12', 20 ),
					'transactionHash' => '0x12a928b0a82cc3f34fbec922a835fb81e494af8b497445b187c5b678ecb2dc4f',
				),
			),
		);
		return array_replace_recursive( $event, $overrides );
	}

	private function decoder(): ContractEventDecoder {
		return new ContractEventDecoder( new Settings() );
	}

	public function test_decodes_a_verified_attestation(): void {
		$a = $this->decoder()->decode( self::delivery() );

		$this->assertNotNull( $a );
		$this->assertSame( str_repeat( 'ab', 32 ), $a->correlation_id );
		$this->assertTrue( $a->is_verified() );
		$this->assertSame( str_repeat( 'cd', 32 ), $a->subject_commitment );
		$this->assertSame( str_repeat( 'ef', 32 ), $a->presentation_hash, 'hex is lower-cased' );
		$this->assertSame( 'e1bf9817-a9d5-41a0-9b76-48d4d9767db4', $a->event_id );
	}

	public function test_accepts_numeric_result(): void {
		$a = $this->decoder()->decode( self::delivery( array(), array( 'result' => 2 ) ) );
		$this->assertSame( Attestation::RESULT_REJECTED, $a?->result );
	}

	public function test_ignores_other_listeners(): void {
		$this->assertNull( $this->decoder()->decode( self::delivery( array( 'blockchainEvent' => array( 'listener' => 'someone-else' ) ) ) ) );
	}

	public function test_listener_id_case_does_not_matter(): void {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array(
			'firefly_listener_id' => strtoupper( self::LISTENER ),
			'attestor_address'    => '0x' . str_repeat( '12', 20 ),
		);
		$this->assertNotNull( $this->decoder()->decode( self::delivery() ) );
	}

	public function test_ignores_a_log_removed_by_a_reorg(): void {
		$this->assertNull( $this->decoder()->decode( self::delivery( array( 'blockchainEvent' => array( 'info' => array( 'removed' => true ) ) ) ) ) );
		$this->assertNotNull( $this->decoder()->decode( self::delivery( array( 'blockchainEvent' => array( 'info' => array( 'removed' => false ) ) ) ) ) );
	}

	public function test_ignores_everything_when_no_listener_is_configured(): void {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array();
		$this->assertNull( $this->decoder()->decode( self::delivery() ) );
	}

	public function test_ignores_other_event_types_and_names(): void {
		$this->assertNull( $this->decoder()->decode( self::delivery( array( 'type' => 'message_confirmed' ) ) ) );
		$this->assertNull( $this->decoder()->decode( self::delivery( array( 'blockchainEvent' => array( 'name' => 'Transfer' ) ) ) ) );
	}

	public function test_ignores_a_malformed_correlation_id(): void {
		$this->assertNull( $this->decoder()->decode( self::delivery( array(), array( 'correlationId' => '0x1234' ) ) ) );
	}

	public function test_an_unreadable_result_counts_as_rejected(): void {
		$a = $this->decoder()->decode( self::delivery( array(), array( 'result' => 'yes' ) ) );
		$this->assertFalse( $a?->is_verified() );
	}

	public function test_rejects_another_emitter_and_missing_address(): void {
		foreach ( array( '', '0x' . str_repeat( '34', 20 ) ) as $address ) {
			$this->assertNull( $this->decoder()->decode( self::delivery( array( 'blockchainEvent' => array( 'info' => array( 'address' => $address ) ) ) ) ) );
		}
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ]['attestor_address'] = '';
		$this->assertNull( $this->decoder()->decode( self::delivery() ) );
	}

	public function test_hex32(): void {
		$this->assertSame( str_repeat( '0a', 32 ), ContractEventDecoder::hex32( '0x' . str_repeat( '0A', 32 ) ) );
		$this->assertNull( ContractEventDecoder::hex32( '0x' . str_repeat( 'zz', 32 ) ) );
		$this->assertNull( ContractEventDecoder::hex32( 42 ) );
	}
}
