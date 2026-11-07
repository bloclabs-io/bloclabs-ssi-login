<?php
/**
 * One application token, as issued: the secret the agent gets once, and the
 * row the tokens table keeps (ADR 0007 §4).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Login;

final class IssuedToken {

	/**
	 * @param string       $token              The secret, `bssi_…`. Returned to the agent once; never stored, logged or passed to a hook.
	 * @param int          $user_id            The account the token acts as.
	 * @param bool         $delegated          True when `acts_for` named the account; false when the agent's own key is linked to it.
	 * @param string       $agent_subject_hash HMAC of the agent's subject id under the subject key, as in the identities table.
	 * @param string       $agent_label        A label for people: the agent's name and operator, or a keyed fingerprint.
	 * @param string|null  $issuer             The agent credential's issuer.
	 * @param list<string> $scope              Scope names granted.
	 * @param string       $correlation_id     The on-chain decision this token came from.
	 * @param string|null  $tx_ref             Its transaction reference, as FireFly reported it.
	 * @param string|null  $firefly_event_id   Its FireFly event.
	 * @param int          $created_at         Unix time.
	 * @param int          $expires_at         Unix time: issuance plus the TTL, or the credential's expiry if sooner.
	 */
	public function __construct(
		public readonly string $token,
		public readonly int $user_id,
		public readonly bool $delegated,
		public readonly string $agent_subject_hash,
		public readonly string $agent_label,
		public readonly ?string $issuer,
		public readonly array $scope,
		public readonly string $correlation_id,
		public readonly ?string $tx_ref,
		public readonly ?string $firefly_event_id,
		public readonly int $created_at,
		public readonly int $expires_at,
	) {}

	/**
	 * What the tokens table stores. The secret is not in it: only its hash.
	 *
	 * @return array<string, scalar|null>
	 */
	public function to_row(): array {
		return array(
			'token_hash'         => AgentToken::hash( $this->token ),
			'user_id'            => $this->user_id,
			'delegated'          => $this->delegated ? 1 : 0,
			'agent_subject_hash' => $this->agent_subject_hash,
			'agent_label'        => $this->agent_label,
			'issuer'             => $this->issuer,
			'scope'              => (string) wp_json_encode( $this->scope ),
			'correlation_id'     => $this->correlation_id,
			'tx_ref'             => $this->tx_ref,
			'firefly_event_id'   => $this->firefly_event_id,
			'created_at'         => gmdate( 'Y-m-d H:i:s', $this->created_at ),
			'expires_at'         => gmdate( 'Y-m-d H:i:s', $this->expires_at ),
		);
	}
}
