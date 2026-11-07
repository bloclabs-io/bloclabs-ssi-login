<?php
/**
 * Which account an agent token acts as (ADR 0007 §3, step 4; #90): `acts_for`
 * with the principal's opt-in, else the agent's own linked key, never a new account.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Identity\AgentAccount;
use BlocLabs\SsiLogin\Identity\AgentDelegation;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Verifier\PresentationResult;

final class AgentResolutionTest extends IntegrationTestCase {

	private const AGENT = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

	private const PRINCIPAL = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

	/**
	 * @param array<string, mixed> $claims
	 */
	private static function presented( array $claims = array() ): PresentationResult {
		return new PresentationResult( self::AGENT, 'did:web:agents.example', str_repeat( 'ab', 32 ), $claims );
	}

	private function resolve( PresentationResult $result ): ?AgentAccount {
		return Plugin::instance()->users()->resolve_agent( $result );
	}

	public function test_acts_for_resolves_to_the_principal_who_opted_in(): void {
		$principal = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->link_subject( $principal, self::PRINCIPAL );
		AgentDelegation::allow( $principal, true );

		$account = $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) );

		$this->assertInstanceOf( AgentAccount::class, $account );
		$this->assertSame( $principal, $account->user->ID );
		$this->assertTrue( $account->delegated );
	}

	public function test_acts_for_is_refused_until_the_principal_opts_in(): void {
		$principal = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->link_subject( $principal, self::PRINCIPAL );

		$this->assertNull( $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ), 'off by default' );

		AgentDelegation::allow( $principal, true );
		$this->assertNotNull( $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ) );

		AgentDelegation::allow( $principal, false );
		$this->assertNull( $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ), 'turned off again' );
	}

	public function test_the_opt_in_belongs_to_this_site(): void {
		global $wpdb;

		$this->assertSame( $wpdb->get_blog_prefix() . 'bloclabs_ssi_agents_allowed', AgentDelegation::meta_key() );

		$principal = self::factory()->user->create( array( 'role' => 'editor' ) );
		update_user_meta( $principal, 'bloclabs_ssi_agents_allowed', '1' );
		$this->assertFalse( AgentDelegation::allowed( $principal ), 'the unprefixed key is not the opt-in' );
		update_user_meta( $principal, AgentDelegation::meta_key(), 'yes' );
		$this->assertFalse( AgentDelegation::allowed( $principal ), 'only "1" counts' );
	}

	public function test_acts_for_naming_nobody_here_is_refused_and_nothing_is_provisioned(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		$before = count_users()['total_users'];

		$this->assertNull( $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ) );
		$this->assertNull( $this->resolve( self::presented( array( 'acts_for' => 'did:example:nobody' ) ) ) );

		$this->assertSame( $before, count_users()['total_users'] );
	}

	public function test_a_delegation_does_not_fall_back_to_the_agents_own_linked_key(): void {
		$own = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $own, self::AGENT );
		$principal = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->link_subject( $principal, self::PRINCIPAL );

		$this->assertNull( $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ), 'the principal did not opt in; the agent does not become itself instead' );
	}

	public function test_without_acts_for_the_agents_own_linked_key_logs_it_in_as_that_account(): void {
		global $wpdb;
		$own = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $own, self::AGENT );

		$account = $this->resolve( self::presented( array( 'agent' => array( 'name' => 'Deploy bot' ) ) ) );

		$this->assertInstanceOf( AgentAccount::class, $account );
		$this->assertSame( $own, $account->user->ID );
		$this->assertFalse( $account->delegated );
		$last = $wpdb->get_var( $wpdb->prepare( "SELECT last_login_at FROM {$wpdb->prefix}bloclabs_ssi_identities WHERE subject_hash = %s", $this->subject_hash( self::AGENT ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$this->assertNotNull( $last, 'the link records the use' );
	}

	public function test_an_unknown_agent_key_never_gets_an_account_whatever_the_linking_policy(): void {
		$this->configure( array( 'linking_policy' => Settings::AUTO_PROVISION ) );
		$before = count_users()['total_users'];

		$this->assertNull( $this->resolve( self::presented() ) );

		$this->assertSame( $before, count_users()['total_users'] );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash( self::AGENT ) ) );
	}

	public function test_a_link_to_a_deleted_principal_is_no_delegation_and_is_dropped(): void {
		$principal = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->link_subject( $principal, self::PRINCIPAL );
		AgentDelegation::allow( $principal, true );
		// Bypass the hooks that would unlink, so the stale row is really there.
		remove_all_actions( 'deleted_user' );
		remove_all_actions( 'remove_user_from_blog' );
		require_once ABSPATH . 'wp-admin/includes/user.php';
		if ( is_multisite() ) {
			require_once ABSPATH . 'wp-admin/includes/ms.php';
			wpmu_delete_user( $principal );
		} else {
			wp_delete_user( $principal );
		}
		$this->assertSame( $principal, Plugin::instance()->identities()->user_id_for( $this->subject_hash( self::PRINCIPAL ) ), 'stale link in place' );

		$this->assertNull( $this->resolve( self::presented( array( 'acts_for' => self::PRINCIPAL ) ) ) );
		$this->assertNull( Plugin::instance()->identities()->user_id_for( $this->subject_hash( self::PRINCIPAL ) ), 'dropped' );
	}
}
