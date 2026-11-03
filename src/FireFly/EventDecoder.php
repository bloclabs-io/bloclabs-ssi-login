<?php
/**
 * Turns a FireFly event into an Attestation, or null when it is not one.
 *
 * Swap the implementation (filter `bloclabs_ssi_event_decoder`) to match a
 * different contract or event layout without touching the rest of the plugin.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\FireFly;

interface EventDecoder {

	/**
	 * @param array<string, mixed> $event A FireFly event with its reference embedded.
	 */
	public function decode( array $event ): ?Attestation;
}
