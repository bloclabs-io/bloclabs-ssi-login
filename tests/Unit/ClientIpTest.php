<?php
/**
 * The rate-limit key: which address counts, and what counts as one client (#26).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Support\ClientIp;
use PHPUnit\Framework\TestCase;

final class ClientIpTest extends TestCase {

	private const CLIENT = '203.0.113.50';

	/** @var array<string, mixed> */
	private array $server = array();

	protected function setUp(): void {
		$this->server = $_SERVER;
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CF_CONNECTING_IP'] );
		$_SERVER['REMOTE_ADDR'] = '198.51.100.1';

		$GLOBALS['bloclabs_ssi_test_options'] = array( Settings::SUBJECT_KEY_OPTION => str_repeat( 'ab', 32 ) );
	}

	protected function tearDown(): void {
		$_SERVER                              = $this->server;
		$GLOBALS['bloclabs_ssi_test_options'] = array();
	}

	/**
	 * @param array<string, mixed> $values
	 */
	private function settings( array $values = array() ): Settings {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = $values;
		return new Settings();
	}

	public function test_remote_addr_by_default_even_when_a_header_is_sent(): void {
		$_SERVER['HTTP_X_FORWARDED_FOR'] = self::CLIENT;

		$this->assertSame( '198.51.100.1', ClientIp::address( $this->settings() ) );
	}

	/**
	 * M2: proxies append their peer, so the sender owns the left-most entries.
	 */
	public function test_a_forwarded_list_yields_the_entry_the_proxy_appended(): void {
		$settings = $this->settings( array( 'client_ip_header' => 'HTTP_X_FORWARDED_FOR' ) );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = self::CLIENT;
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ), 'a client that sent no header' );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.1, ' . self::CLIENT;
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ), 'a forged entry is ignored' );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '192.0.2.77,10.0.0.1 , ' . self::CLIENT;
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ), 'a victim placed first is not charged' );
	}

	public function test_the_client_sits_as_many_entries_from_the_right_as_there_are_proxies(): void {
		$settings = $this->settings(
			array(
				'client_ip_header'  => 'HTTP_X_FORWARDED_FOR',
				'client_ip_proxies' => 2,
			)
		);

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '10.0.0.1, ' . self::CLIENT . ', 192.0.2.10';
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ) );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = self::CLIENT . ', 192.0.2.10';
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ) );
	}

	public function test_a_header_that_cannot_name_the_client_is_refused(): void {
		$settings = $this->settings(
			array(
				'client_ip_header'  => 'HTTP_X_FORWARDED_FOR',
				'client_ip_proxies' => 2,
			)
		);

		$_SERVER['HTTP_X_FORWARDED_FOR'] = self::CLIENT;
		$this->assertNull( ClientIp::address( $settings ), 'fewer entries than proxies: the second proxy is missing' );
		$this->assertNull( ClientIp::hash( $settings ) );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = 'unknown, ' . self::CLIENT . ', 192.0.2.10';
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ), 'garbage to the left does not matter' );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = self::CLIENT . ', unknown, 192.0.2.10';
		$this->assertNull( ClientIp::address( $settings ), 'garbage in the client slot does' );
	}

	public function test_a_missing_header_means_the_request_bypassed_the_proxy(): void {
		$settings = $this->settings( array( 'client_ip_header' => 'HTTP_CF_CONNECTING_IP' ) );

		$this->assertSame( '198.51.100.1', ClientIp::address( $settings ) );

		$_SERVER['HTTP_CF_CONNECTING_IP'] = self::CLIENT;
		$this->assertSame( self::CLIENT, ClientIp::address( $settings ), 'a single-valued header is the one-proxy case' );
	}

	public function test_fewer_than_one_proxy_still_trusts_the_last_entry(): void {
		$this->assertSame( self::CLIENT, ClientIp::forwarded( '10.0.0.1, ' . self::CLIENT, 0 ) );
		$this->assertNull( ClientIp::forwarded( '', 1 ) );
		$this->assertNull( ClientIp::forwarded( 'not-an-ip', 1 ) );
	}

	/**
	 * L19: a /64 holder cannot rotate out of the cap, and a dual-stack server's
	 * IPv4-mapped form of an address is the same client as the address.
	 */
	public function test_buckets(): void {
		$this->assertSame( '203.0.113.50', ClientIp::bucket( '203.0.113.50' ) );
		$this->assertSame( '203.0.113.50', ClientIp::bucket( '::ffff:203.0.113.50' ) );
		$this->assertSame( '2001:db8:1:2::/64', ClientIp::bucket( '2001:db8:1:2::1' ) );
		$this->assertSame( '2001:db8:1:2::/64', ClientIp::bucket( '2001:db8:1:2:ffff:ffff:ffff:ffff' ) );
		$this->assertSame( '2001:db8:1:3::/64', ClientIp::bucket( '2001:db8:1:3::1' ) );
		$this->assertSame( 'not-an-ip', ClientIp::bucket( 'not-an-ip' ) );
	}

	public function test_hash_keys_the_bucket_not_the_address(): void {
		$settings = $this->settings();

		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::1';
		$a                      = ClientIp::hash( $settings );
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:ffff::9';
		$b                      = ClientIp::hash( $settings );
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:3::1';
		$c                      = ClientIp::hash( $settings );

		$this->assertNotNull( $a );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', (string) $a );
		$this->assertSame( $a, $b, 'one /64 is one client' );
		$this->assertNotSame( $a, $c, 'the next /64 is another' );

		$_SERVER['REMOTE_ADDR'] = self::CLIENT;
		$v4                     = ClientIp::hash( $settings );
		$_SERVER['REMOTE_ADDR'] = '::ffff:' . self::CLIENT;
		$this->assertSame( $v4, ClientIp::hash( $settings ), 'IPv4-mapped is the IPv4 client' );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.51';
		$this->assertNotSame( $v4, ClientIp::hash( $settings ) );

		$this->assertSame( hash_hmac( 'sha256', self::CLIENT, str_repeat( 'ab', 32 ) ), $v4, 'the key is the plugin subject key' );
	}
}
