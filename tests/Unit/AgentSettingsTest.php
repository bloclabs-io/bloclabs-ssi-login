<?php
/**
 * The agent login settings of ADR 0007 §6 (#90).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Config\Settings;
use PHPUnit\Framework\TestCase;

final class AgentSettingsTest extends TestCase {

	protected function tearDown(): void {
		$GLOBALS['bloclabs_ssi_test_options'] = array();
	}

	/**
	 * @param array<string, mixed> $stored
	 */
	private static function settings( array $stored ): Settings {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = $stored;
		return new Settings();
	}

	public function test_agent_login_is_off_by_default_and_needs_credential_login_on(): void {
		$this->assertFalse( ( new Settings() )->agent_login_enabled() );
		$this->assertFalse( self::settings( array( 'agent_login_enabled' => true ) )->agent_login_enabled(), 'credential login off: agents off' );
		$this->assertFalse( self::settings( array( 'enabled' => true ) )->agent_login_enabled() );
		$this->assertTrue(
			self::settings(
				array(
					'enabled'             => true,
					'agent_login_enabled' => true,
				)
			)->agent_login_enabled()
		);
	}

	public function test_the_defaults_follow_the_adr(): void {
		$settings = new Settings();

		$this->assertSame( 'agent', $settings->string( 'agent_credential_query' ) );
		$this->assertSame( 3600, $settings->agent_token_ttl() );
		$this->assertSame( 'read,content', $settings->string( 'agent_scopes' ) );
	}

	public function test_the_token_lifetime_is_clamped_to_five_minutes_and_a_day(): void {
		$this->assertSame( 300, self::settings( array( 'agent_token_ttl' => 0 ) )->agent_token_ttl() );
		$this->assertSame( 300, self::settings( array( 'agent_token_ttl' => 299 ) )->agent_token_ttl() );
		$this->assertSame( 300, self::settings( array( 'agent_token_ttl' => -1 ) )->agent_token_ttl() );
		$this->assertSame( 900, self::settings( array( 'agent_token_ttl' => '900' ) )->agent_token_ttl() );
		$this->assertSame( 86400, self::settings( array( 'agent_token_ttl' => 86401 ) )->agent_token_ttl() );
		$this->assertSame( 86400, self::settings( array( 'agent_token_ttl' => PHP_INT_MAX ) )->agent_token_ttl() );
	}
}
