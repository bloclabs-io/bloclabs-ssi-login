<?php
/**
 * What WordPress asks the verifier for.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Verifier;

final class PresentationRequest {

	/**
	 * @param string $correlation_id Echoed on chain in the LoginAttested event.
	 * @param string $nonce          Must be bound into the presentation (key-binding JWT / device signature).
	 * @param string $query          Name of a credential query (DCQL) configured in the verifier.
	 * @param int    $expires_at     Unix time after which the verifier must refuse responses.
	 */
	public function __construct(
		public readonly string $correlation_id,
		public readonly string $nonce,
		public readonly string $query,
		public readonly int $expires_at,
	) {}

	/**
	 * @return array<string, scalar>
	 */
	public function to_array(): array {
		return array(
			'correlation_id' => $this->correlation_id,
			'nonce'          => $this->nonce,
			'query'          => $this->query,
			'expires_at'     => gmdate( 'Y-m-d\TH:i:s\Z', $this->expires_at ),
		);
	}
}
