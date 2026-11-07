<?php
/**
 * Reads the agent credential's claims (ADR 0007 §1) out of a verifier result.
 *
 * The claims are authenticated bridge HTTP data, like `issuer` and `claims`
 * for a person (ARCHITECTURE.md, trust boundary 5). None of them is on chain.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

use BlocLabs\SsiLogin\Login\Scope;
use BlocLabs\SsiLogin\Verifier\PresentationResult;

final class AgentCredential {

	/** Longest label the tokens table keeps. */
	private const LABEL_LENGTH = 191;

	/**
	 * Who the agent acts for: the principal's subject id, as the bridge derives
	 * it from the principal's own credential. Null when the credential names
	 * nobody (then only the agent's own linked key can log it in).
	 */
	public static function acts_for( PresentationResult $result ): ?string {
		$value = $result->claims['acts_for'] ?? null;
		if ( ! is_string( $value ) ) {
			return null;
		}
		$value = trim( $value );
		return '' !== $value ? $value : null;
	}

	/**
	 * The most the issuer lets this agent do. Null when the credential sets no
	 * limit; a list (possibly empty, which refuses everything) when it does,
	 * so a malformed claim never widens anything.
	 *
	 * @return list<string>|null
	 */
	public static function scope( PresentationResult $result ): ?array {
		if ( ! array_key_exists( 'scope', $result->claims ) ) {
			return null;
		}
		return Scope::names( $result->claims['scope'] );
	}

	/**
	 * A label for people: the sanitised `agent.name` (and `operator`), or the
	 * keyed fingerprint an identity link gets. Never used for a decision.
	 *
	 * @param string $key The subject key, for the fingerprint.
	 */
	public static function label( PresentationResult $result, string $key ): string {
		$agent = $result->claims['agent'] ?? null;
		$parts = array();
		if ( is_array( $agent ) ) {
			foreach ( array( 'name', 'operator' ) as $field ) {
				$value = isset( $agent[ $field ] ) && is_string( $agent[ $field ] ) ? sanitize_text_field( $agent[ $field ] ) : '';
				if ( '' !== $value ) {
					$parts[] = $value;
				}
			}
		}
		if ( array() === $parts ) {
			return IdentityRepository::label( $result->subject_id, $key );
		}
		$label = 2 === count( $parts ) ? $parts[0] . ' (' . $parts[1] . ')' : $parts[0];
		return mb_substr( $label, 0, self::LABEL_LENGTH );
	}
}
