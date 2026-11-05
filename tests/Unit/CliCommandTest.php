<?php
/**
 * wp bloclabs-ssi subscribe: the webhook address option (#39).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Cli\Command;
use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Plugin;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

final class CliCommandTest extends TestCase {

	/**
	 * WP-CLI's own options: every entry of its php/config-spec.php with a
	 * `runtime` form. WP_CLI\Configurator::unmix_assoc_args() moves these from
	 * a command's $assoc_args into WP-CLI's runtime config, so a command that
	 * declares one of them never receives it (#39: `--url` is the site URL).
	 */
	private const WP_CLI_GLOBAL_OPTIONS = array(
		'path',
		'url',
		'ssh',
		'http',
		'user',
		'skip-plugins',
		'skip-themes',
		'skip-packages',
		'require',
		'exec',
		'context',
		'color',
		'debug',
		'prompt',
		'quiet',
	);

	private const WEBHOOK_URL = 'http://wordpress/wp-json/bloclabs-ssi/v1/firefly/events';

	protected function setUp(): void {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ] = array(
			'firefly_listener_id' => 'listener-1',
			'webhook_secret'      => str_repeat( 's', 32 ),
		);
		$GLOBALS['bloclabs_ssi_test_remote_requests']             = array();
		$GLOBALS['bloclabs_ssi_test_remote_response']             = array(
			'response' => array( 'code' => 201 ),
			'body'     => '{"id":"sub-1"}',
		);
		\WP_CLI::$lines = array();
	}

	protected function tearDown(): void {
		unset( $GLOBALS['bloclabs_ssi_test_remote_callback'], $GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ], $GLOBALS['bloclabs_ssi_test_remote_response'] );
	}

	public function test_no_subcommand_declares_an_option_wp_cli_keeps_for_itself(): void {
		$declared = array();
		foreach ( ( new ReflectionClass( Command::class ) )->getMethods( ReflectionMethod::IS_PUBLIC ) as $method ) {
			if ( $method->isStatic() || $method->isConstructor() ) {
				continue;
			}
			foreach ( self::declared_options( $method ) as $option ) {
				$declared[] = $option;
				$this->assertNotContains(
					$option,
					self::WP_CLI_GLOBAL_OPTIONS,
					"wp bloclabs-ssi {$method->getName()} declares --{$option}, which WP-CLI consumes as its own global option"
				);
			}
		}
		$this->assertContains( 'webhook-url', $declared, 'subscribe takes the webhook address as --webhook-url' );
	}

	public function test_subscribe_sends_the_webhook_url_option_to_firefly(): void {
		( new Command( Plugin::instance() ) )->subscribe( array(), array( 'webhook-url' => self::WEBHOOK_URL ) );

		$subscription = $this->subscription();
		$this->assertSame( self::WEBHOOK_URL, $subscription['options']['url'] );
		$this->assertSame( 'listener-1', $subscription['filter']['blockchainevent']['listener'] );
		$this->assertContains( 'Success: Subscription sub-1 saved.', \WP_CLI::$lines );
	}

	public function test_subscribe_defaults_to_the_site_rest_url(): void {
		( new Command( Plugin::instance() ) )->subscribe( array(), array() );

		$this->assertSame( rest_url( 'bloclabs-ssi/v1/firefly/events' ), $this->subscription()['options']['url'] );
	}

	public function test_subscribe_does_not_read_a_url_argument(): void {
		// WP-CLI never passes --url on; if it did, it would be the site URL, not the webhook address.
		( new Command( Plugin::instance() ) )->subscribe( array(), array( 'url' => self::WEBHOOK_URL ) );

		$this->assertSame( rest_url( 'bloclabs-ssi/v1/firefly/events' ), $this->subscription()['options']['url'] );
	}

	public function test_status_warns_on_unbound_listener_and_rotated_subscription(): void {
		$GLOBALS['bloclabs_ssi_test_remote_callback'] = static function ( string $url ): array {
			$body = str_ends_with( $url, '/subscriptions' ) ? array(
				array(
					'name'      => 'bloclabs-ssi-login',
					'transport' => 'webhooks',
					'options'   => array(
						'url'     => 'https://old.example/events',
						'headers' => array( 'X-SSI-Secret' => 'old-secret' ),
					),
				),
			) : array();
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $body ),
			);
		};
		( new Command( Plugin::instance() ) )->status( array(), array() );
		$this->assertContains( 'Warning: The contract listener has no address binding.', \WP_CLI::$lines );
		$this->assertContains( 'Warning: Subscription URL or secret differs; run subscribe to update it.', \WP_CLI::$lines );
		$this->assertStringNotContainsString( 'old-secret', implode( '\n', \WP_CLI::$lines ) );
	}

	public function test_subscribe_replaces_the_existing_secret_using_put(): void {
		$GLOBALS['bloclabs_ssi_test_options'][ Settings::OPTION ]['webhook_secret'] = str_repeat( 'r', 32 );
		Plugin::instance()->settings()->flush();
		( new Command( Plugin::instance() ) )->subscribe( array(), array( 'webhook-url' => self::WEBHOOK_URL ) );
		$subscription = $this->subscription();
		$this->assertContains( str_repeat( 'r', 32 ), $subscription['options']['headers'] );
	}

	/**
	 * The one subscription the command posted to FireFly.
	 *
	 * @return array<string, mixed>
	 */
	private function subscription(): array {
		$requests = $GLOBALS['bloclabs_ssi_test_remote_requests'];
		$this->assertCount( 1, $requests );
		$this->assertStringEndsWith( '/api/v1/namespaces/default/subscriptions', $requests[0]['url'] );
		$this->assertSame( 'PUT', $requests[0]['args']['method'] );
		$this->assertSame( 'application/json', $requests[0]['args']['headers']['Content-Type'] );

		return json_decode( (string) $requests[0]['args']['body'], true );
	}

	/**
	 * The `--option` names a subcommand's docblock declares (`[--name=<value>]`, `--name`).
	 *
	 * @return list<string>
	 */
	private static function declared_options( ReflectionMethod $method ): array {
		preg_match_all( '/^\s*\*\s*\[?--([a-z0-9-]+)/m', (string) $method->getDocComment(), $matches );
		return $matches[1];
	}
}
