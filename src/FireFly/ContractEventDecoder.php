<?php
/**
 * Decodes the LoginAttested event of contracts/SsiLoginAttestor.sol:
 *
 *   event LoginAttested(bytes32 indexed correlationId, uint8 result,
 *                       bytes32 subjectCommitment, bytes32 presentationHash,
 *                       address indexed verifier);
 *
 * FireFly delivers it as a `blockchain_event_received` event whose
 * `blockchainEvent.output` holds the decoded parameters.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

use BlocLabs\SsiLogin\Config\Settings;

final class ContractEventDecoder implements EventDecoder {

	public function __construct( private readonly Settings $settings ) {}

	public function decode( array $event ): ?Attestation {
		if ( 'blockchain_event_received' !== ( $event['type'] ?? null ) ) {
			return null;
		}

		$chain_event = $event['blockchainEvent'] ?? null;
		if ( ! is_array( $chain_event ) ) {
			return null;
		}

		if ( $this->settings->string( 'attestation_event' ) !== ( $chain_event['name'] ?? null ) ) {
			return null;
		}

		// Only the configured listener is trusted: it is bound to the attestor contract's address.
		$listener = strtolower( $this->settings->string( 'firefly_listener_id' ) );
		if ( '' === $listener || strtolower( (string) ( $chain_event['listener'] ?? '' ) ) !== $listener ) {
			return null;
		}

		// A log dropped by a chain reorganisation is not a decision. Ignore it (no rejection either):
		// if the transaction is mined again, its new log arrives as a new event.
		if ( true === ( $chain_event['info']['removed'] ?? false ) ) {
			return null;
		}

		$output      = is_array( $chain_event['output'] ?? null ) ? $chain_event['output'] : array();
		$correlation = self::hex32( $output['correlationId'] ?? null );
		if ( null === $correlation ) {
			return null;
		}

		$result = filter_var( $output['result'] ?? null, FILTER_VALIDATE_INT );

		return new Attestation(
			$correlation,
			false === $result ? Attestation::RESULT_REJECTED : $result,
			self::hex32( $output['subjectCommitment'] ?? null ),
			self::hex32( $output['presentationHash'] ?? null ),
			(string) ( $event['id'] ?? '' ),
			isset( $chain_event['info']['transactionHash'] ) ? (string) $chain_event['info']['transactionHash'] : null,
		);
	}

	/**
	 * Normalises a bytes32 value ("0x" + 64 hex) to 64 lowercase hex characters.
	 *
	 * @param mixed $value
	 */
	public static function hex32( $value ): ?string {
		if ( ! is_string( $value ) ) {
			return null;
		}
		$hex = strtolower( str_starts_with( $value, '0x' ) ? substr( $value, 2 ) : $value );
		return 1 === preg_match( '/^[0-9a-f]{64}$/', $hex ) ? $hex : null;
	}
}
