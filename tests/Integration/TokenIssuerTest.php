<?php
/**
 * Issuing an application token for a verified agent attempt (ADR 0007 §3 and §4; #90).
 *
 * The tokens table is follow-up 1/7; until it lands the issuer writes through a
 * TokenStore double that records what it would have stored.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Identity\AgentDelegation;
use BlocLabs\SsiLogin\Login\AgentToken;
use BlocLabs\SsiLogin\Login\IssuedToken;
use BlocLabs\SsiLogin\Login\TokenIssuer;
use BlocLabs\SsiLogin\Login\TokenStore;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent;
use BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake;
use BlocLabs\SsiLogin\Verifier\VerifierException;

final class TokenIssuerTest extends IntegrationTestCase {

	private const PRINCIPAL = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

	/** @var TokenStore&object{stored: list<IssuedToken>, fail: bool} */
	private TokenStore $store;

	private TokenIssuer $issuer;

	/** @var list<string> */
	private array $logins = array();

	protected function setUp(): void {
		parent::setUp();
		$this->store  = new class() implements TokenStore {
			/** @var list<IssuedToken> */
			public array $stored = array();
			public bool $fail    = false;

			public function store( IssuedToken $token ): bool {
				if ( $this->fail ) {
					return false;
				}
				$this->stored[] = $token;
				return true;
			}
		};
		$plugin       = Plugin::instance();
		$this->issuer = new TokenIssuer( $plugin->settings(), $plugin->attempts(), $plugin->checks(), $plugin->users(), $this->store );
		$this->logins = array();
		add_action(
			'wp_login',
			function ( $login ): void {
				$this->logins[] = (string) $login;
			}
		);
	}

	/**
	 * A verified attempt opened for an agent, as `/agent/initiate` (2/7) will open it.
	 *
	 * @return array{public_id: string, row: array<string, mixed>}
	 */
	private function verified_agent_attempt( string $purpose = TokenIssuer::PURPOSE ): array {
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->backdate( $public_id, array( 'purpose' => $purpose ) );
		$this->attest( $opened['row'] );
		$row = $this->attempt_row( $public_id );
		$this->assertNotNull( $row );
		$this->assertSame( 'verified', $row['status'] );
		return array(
			'public_id' => $public_id,
			'row'       => $row,
		);
	}

	private function attempt( string $public_id ): Attempt {
		$attempt = Plugin::instance()->attempts()->find_by_public_id( $public_id );
		$this->assertNotNull( $attempt );
		return $attempt;
	}

	/**
	 * @param list<string> $requested
	 * @return IssuedToken|\WP_Error
	 */
	private function issue( string $public_id, array $requested = array( 'read' ) ) {
		return $this->issuer->issue( $this->attempt( $public_id ), $requested );
	}

	private function assert_refused( $outcome, string $code, int $status, string $public_id, string $attempt_status ): void {
		$this->assertInstanceOf( \WP_Error::class, $outcome );
		$this->assertSame( $code, $outcome->get_error_code() );
		$this->assertSame( $status, $outcome->get_error_data()['status'] ?? null );
		$this->assertSame( $attempt_status, $this->attempt_row( $public_id )['status'] );
		$this->assertSame( array(), $this->store->stored, 'no token was stored' );
	}

	private function linked_agent( string $role = 'subscriber' ): int {
		$user_id = self::factory()->user->create( array( 'role' => $role ) );
		$this->link_subject( $user_id );
		return $user_id;
	}

	public function test_a_verified_agent_attempt_yields_one_token_and_no_session(): void {
		$user_id                         = $this->linked_agent( 'editor' );
		VerifierFake::instance()->claims = array(
			'agent' => array(
				'name'     => 'Deploy bot',
				'operator' => 'Acme',
			),
		);
		$attempt                         = $this->verified_agent_attempt();
		$issued                          = array();
		add_action(
			'bloclabs_ssi_agent_token_issued',
			static function ( $row, $user ) use ( &$issued ): void {
				$issued[] = array( $row, $user );
			},
			10,
			2
		);
		$before = time();

		$token = $this->issue( $attempt['public_id'], array( 'read', 'content' ) );

		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertTrue( AgentToken::is_token( $token->token ) );
		$this->assertSame( $user_id, $token->user_id );
		$this->assertFalse( $token->delegated );
		$this->assertSame( array( 'read', 'content' ), $token->scope );
		$this->assertSame( $this->subject_hash(), $token->agent_subject_hash );
		$this->assertSame( 'Deploy bot (Acme)', $token->agent_label );
		$this->assertSame( 'did:web:issuer.example', $token->issuer );
		$this->assertSame( $attempt['row']['correlation_id'], $token->correlation_id );
		$this->assertNotEmpty( $attempt['row']['tx_ref'] );
		$this->assertSame( $attempt['row']['tx_ref'], $token->tx_ref, 'the on-chain decision travels to the token row' );
		$this->assertSame( $attempt['row']['firefly_event_id'], $token->firefly_event_id );
		$this->assertGreaterThanOrEqual( $before, $token->created_at );
		$this->assertSame( $token->created_at + 3600, $token->expires_at, 'the default TTL' );

		$row = $this->attempt_row( $attempt['public_id'] );
		$this->assertSame( 'consumed', $row['status'] );
		$this->assertSame( $user_id, (int) $row['user_id'] );

		$this->assertCount( 1, $this->store->stored );
		$stored = $this->store->stored[0]->to_row();
		$this->assertSame( hash( 'sha256', $token->token ), $stored['token_hash'] );
		$this->assertArrayNotHasKey( 'token', $stored );
		$this->assertStringNotContainsString( $token->token, (string) wp_json_encode( $stored ), 'the secret is never stored' );
		$this->assertSame( '["read","content"]', $stored['scope'] );
		$this->assertSame( 0, $stored['delegated'] );

		$this->assertCount( 1, $issued );
		$this->assertSame( $stored, $issued[0][0], 'the action gets the row, not the secret' );
		$this->assertSame( $user_id, $issued[0][1]->ID );

		$this->assertSame( array(), $this->auth_cookie_users(), 'no auth cookie' );
		$this->assertSame( 0, get_current_user_id(), 'no session' );
		$this->assertSame( array(), $this->logins, 'wp_login does not fire for a token' );
	}

	public function test_one_attestation_yields_at_most_one_token(): void {
		$this->linked_agent();
		$attempt = $this->verified_agent_attempt();

		$this->assertInstanceOf( IssuedToken::class, $this->issue( $attempt['public_id'] ) );
		$again = $this->issue( $attempt['public_id'] );

		$this->assertInstanceOf( \WP_Error::class, $again );
		$this->assertSame( 'bloclabs_ssi_not_verified', $again->get_error_code(), 'a consumed attempt is no longer verified' );
		$this->assertCount( 1, $this->store->stored );
		$this->assertSame( 1, VerifierFake::instance()->fetches, 'the result is not even fetched again' );
	}

	public function test_a_browser_login_attempt_cannot_become_a_token(): void {
		$this->linked_agent();
		$attempt = $this->verified_agent_attempt( 'login' );

		$outcome = $this->issue( $attempt['public_id'] );

		$this->assert_refused( $outcome, 'bloclabs_ssi_not_verified', 409, $attempt['public_id'], 'verified' );
		$this->assertSame( 0, VerifierFake::instance()->fetches, 'refused before the verifier is asked' );
	}

	public function test_a_profile_link_attempt_cannot_become_a_token(): void {
		$this->linked_agent();
		$attempt = $this->verified_agent_attempt( 'link' );

		$this->assert_refused( $this->issue( $attempt['public_id'] ), 'bloclabs_ssi_not_verified', 409, $attempt['public_id'], 'verified' );
	}

	public function test_a_pending_or_expired_attempt_is_not_issued(): void {
		$this->linked_agent();
		$opened    = $this->open_attempt();
		$public_id = (string) $opened['data']['attempt'];
		$this->backdate( $public_id, array( 'purpose' => TokenIssuer::PURPOSE ) );

		$this->assert_refused( $this->issue( $public_id ), 'bloclabs_ssi_not_verified', 409, $public_id, 'pending' );

		$this->attest( $opened['row'] );
		$this->backdate( $public_id, array( 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ) );
		$this->assert_refused( $this->issue( $public_id ), 'bloclabs_ssi_not_verified', 409, $public_id, 'verified' );
	}

	public function test_a_transient_verifier_error_keeps_the_attempt_verified(): void {
		$this->linked_agent();
		$attempt                               = $this->verified_agent_attempt();
		VerifierFake::instance()->result_error = new VerifierException( 'down', 503 );

		$this->assert_refused( $this->issue( $attempt['public_id'] ), TokenIssuer::RETRY, 503, $attempt['public_id'], 'verified' );

		VerifierFake::instance()->result_error = null;
		$this->assertInstanceOf( IssuedToken::class, $this->issue( $attempt['public_id'] ), 'the agent retries and gets its token' );
	}

	public function test_a_commitment_mismatch_fails_the_attempt(): void {
		$this->linked_agent();
		$attempt                             = $this->verified_agent_attempt();
		VerifierFake::instance()->subject_id = 'did:example:other-subject';
		$mismatched                          = false;
		add_action(
			'bloclabs_ssi_commitment_mismatch',
			static function () use ( &$mismatched ): void {
				$mismatched = true;
			}
		);

		$this->assert_refused( $this->issue( $attempt['public_id'] ), 'bloclabs_ssi_mismatch', 403, $attempt['public_id'], 'failed' );
		$this->assertTrue( $mismatched );
	}

	public function test_an_unlinked_agent_is_refused_and_never_provisioned(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		$attempt = $this->verified_agent_attempt();
		$before  = count_users()['total_users'];

		$this->assert_refused( $this->issue( $attempt['public_id'] ), 'bloclabs_ssi_not_linked', 403, $attempt['public_id'], 'failed' );
		$this->assertSame( $before, count_users()['total_users'] );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash() ) );
	}

	public function test_acts_for_issues_a_delegated_token_only_once_the_principal_opted_in(): void {
		$principal = self::factory()->user->create( array( 'role' => 'author' ) );
		$this->link_subject( $principal, self::PRINCIPAL );
		VerifierFake::instance()->claims = array( 'acts_for' => self::PRINCIPAL );

		$first = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $first['public_id'] ), 'bloclabs_ssi_not_linked', 403, $first['public_id'], 'failed' );

		AgentDelegation::allow( $principal, true );
		$second = $this->verified_agent_attempt();
		$token  = $this->issue( $second['public_id'] );

		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertSame( $principal, $token->user_id );
		$this->assertTrue( $token->delegated );
		$this->assertSame( $this->subject_hash(), $token->agent_subject_hash, 'the agent, not the principal, is the token\'s subject' );
		$this->assertSame( 1, $this->store->stored[0]->to_row()['delegated'] );
	}

	public function test_the_login_filters_refuse_agents_too(): void {
		$this->linked_agent();
		$attempt = $this->verified_agent_attempt();
		add_filter( 'bloclabs_ssi_allow_login', '__return_false' );

		$this->assert_refused( $this->issue( $attempt['public_id'] ), 'bloclabs_ssi_refused', 403, $attempt['public_id'], 'failed' );
		remove_filter( 'bloclabs_ssi_allow_login', '__return_false' );

		$locked = $this->verified_agent_attempt();
		add_filter(
			'wp_authenticate_user',
			static fn () => new \WP_Error( 'locked_out', 'Too many attempts.' )
		);

		$this->assert_refused( $this->issue( $locked['public_id'] ), 'locked_out', 403, $locked['public_id'], 'failed' );
	}

	public function test_scope_is_the_intersection_of_request_credential_and_site(): void {
		$this->linked_agent( 'editor' );

		VerifierFake::instance()->claims = array( 'scope' => array( 'read' ) );
		$narrowed                        = $this->verified_agent_attempt();
		$token                           = $this->issue( $narrowed['public_id'], array( 'content', 'read' ) );
		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertSame( array( 'read' ), $token->scope, 'the credential narrows the request' );

		$nothing             = $this->verified_agent_attempt();
		$this->store->stored = array();
		$this->assert_refused( $this->issue( $nothing['public_id'], array( 'content' ) ), 'bloclabs_ssi_scope', 403, $nothing['public_id'], 'failed' );

		VerifierFake::instance()->claims = null;
		$this->configure( array( 'agent_scopes' => 'read' ) );
		$site = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $site['public_id'], array( 'content' ) ), 'bloclabs_ssi_scope', 403, $site['public_id'], 'failed' );

		$unknown = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $unknown['public_id'], array( 'admin', 'Read' ) ), 'bloclabs_ssi_scope', 403, $unknown['public_id'], 'failed' );

		$empty = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $empty['public_id'], array() ), 'bloclabs_ssi_scope', 403, $empty['public_id'], 'failed' );
	}

	public function test_the_agent_token_filter_narrows_but_never_widens_and_may_refuse(): void {
		$this->linked_agent( 'editor' );
		$seen = null;
		add_filter(
			'bloclabs_ssi_agent_token',
			static function ( $grant, $user, $result, $attempt ) use ( &$seen ) {
				$seen = array( $grant, $user, $result, $attempt );
				return array(
					'scope'      => array( 'read', 'content' ),
					'expires_at' => $grant['expires_at'] + 86400,
				);
			},
			10,
			4
		);
		$widened = $this->verified_agent_attempt();
		$token   = $this->issue( $widened['public_id'], array( 'read' ) );
		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertSame( array( 'read' ), $token->scope, 'content was not requested: the filter cannot add it' );
		$this->assertSame( $token->created_at + 3600, $token->expires_at, 'the filter cannot extend the lifetime' );
		$this->assertSame( array( 'read' ), $seen[0]['scope'] );
		$this->assertInstanceOf( \WP_User::class, $seen[1] );
		$this->assertInstanceOf( Attempt::class, $seen[3] );
		remove_all_filters( 'bloclabs_ssi_agent_token' );

		add_filter(
			'bloclabs_ssi_agent_token',
			static fn ( $grant ) => array(
				'scope'      => array( 'read' ),
				'expires_at' => $grant['expires_at'] - 3000,
			)
		);
		$narrowed = $this->verified_agent_attempt();
		$token    = $this->issue( $narrowed['public_id'], array( 'read', 'content' ) );
		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertSame( array( 'read' ), $token->scope );
		$this->assertSame( $token->created_at + 600, $token->expires_at );
		remove_all_filters( 'bloclabs_ssi_agent_token' );
		$this->store->stored = array();

		add_filter( 'bloclabs_ssi_agent_token', static fn () => new \WP_Error( 'office_hours', 'Agents work 9 to 5.' ) );
		$vetoed = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $vetoed['public_id'] ), 'office_hours', 403, $vetoed['public_id'], 'failed' );
		remove_all_filters( 'bloclabs_ssi_agent_token' );

		add_filter( 'bloclabs_ssi_agent_token', '__return_false' );
		$refused = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $refused['public_id'] ), 'bloclabs_ssi_refused', 403, $refused['public_id'], 'failed' );
		remove_all_filters( 'bloclabs_ssi_agent_token' );

		add_filter(
			'bloclabs_ssi_agent_token',
			static fn ( $grant ) => array(
				'scope'      => array( 'read' ),
				'expires_at' => time() - 1,
			) + $grant
		);
		$past = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $past['public_id'] ), 'bloclabs_ssi_token_lifetime', 403, $past['public_id'], 'failed' );
	}

	public function test_the_token_never_outlives_the_credential(): void {
		$this->linked_agent();
		$this->configure( array( 'agent_token_ttl' => 7200 ) );

		VerifierFake::instance()->expires_at = time() + 900;
		$soon                                = $this->verified_agent_attempt();
		$token                               = $this->issue( $soon['public_id'] );
		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertSame( VerifierFake::instance()->expires_at, $token->expires_at, 'the credential expires first' );

		VerifierFake::instance()->expires_at = time() + 86400 * 30;
		$later                               = $this->verified_agent_attempt();
		$token                               = $this->issue( $later['public_id'] );
		$this->assertInstanceOf( IssuedToken::class, $token );
		$this->assertSame( $token->created_at + 7200, $token->expires_at, 'the TTL expires first' );

		VerifierFake::instance()->expires_at = time() - 1;
		$this->store->stored                 = array();
		$expired                             = $this->verified_agent_attempt();
		$this->assert_refused( $this->issue( $expired['public_id'] ), 'bloclabs_ssi_token_lifetime', 403, $expired['public_id'], 'failed' );
	}

	public function test_a_failed_token_write_spends_the_attestation_without_a_token(): void {
		$this->linked_agent();
		$attempt           = $this->verified_agent_attempt();
		$this->store->fail = true;

		$outcome = $this->issue( $attempt['public_id'] );

		$this->assertInstanceOf( \WP_Error::class, $outcome );
		$this->assertSame( 'bloclabs_ssi_token_storage', $outcome->get_error_code() );
		$this->assertSame( 503, $outcome->get_error_data()['status'] );
		$this->assertSame( 'consumed', $this->attempt_row( $attempt['public_id'] )['status'], 'spent, so it cannot be tried again' );
		$this->assertSame( array(), $this->store->stored );

		$this->store->fail = false;
		$this->assertSame( 'bloclabs_ssi_not_verified', $this->issue( $attempt['public_id'] )->get_error_code(), 'the agent presents again' );
	}

	public function test_the_fixture_attestation_carries_the_audit_fields_the_token_copies(): void {
		$fixture = CapturedLoginEvent::fixture();
		$this->assertArrayHasKey( 'subject', $fixture );
		$this->linked_agent();
		$attempt = $this->verified_agent_attempt();
		$this->assertNotEmpty( $attempt['row']['firefly_event_id'] );
		$this->assertNotEmpty( $attempt['row']['tx_ref'] );
		$object = $this->attempt( $attempt['public_id'] );
		$this->assertSame( $attempt['row']['tx_ref'], $object->tx_ref );
		$this->assertSame( $attempt['row']['firefly_event_id'], $object->firefly_event_id );
	}
}
