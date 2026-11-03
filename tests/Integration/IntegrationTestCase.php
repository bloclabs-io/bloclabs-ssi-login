<?php
/**
 * Shared WordPress fixtures for the REST and login integration tests.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Database\Schema;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Plugin;
use BlocLabs\SsiLogin\Rest\BrowserController;
use BlocLabs\SsiLogin\Rest\PageToken;
use BlocLabs\SsiLogin\Rest\Routes;
use BlocLabs\SsiLogin\Rest\WebhookController;
use BlocLabs\SsiLogin\Tests\Integration\Support\CapturedLoginEvent;
use BlocLabs\SsiLogin\Tests\Integration\Support\FireFlyHttpFake;
use BlocLabs\SsiLogin\Tests\Integration\Support\VerifierFake;

abstract class IntegrationTestCase extends \WP_UnitTestCase {

	/**
	 * Longer than the 32-character minimum the webhook compares in constant time.
	 */
	protected const WEBHOOK_SECRET = 'integration-test-webhook-secret-value';

	/**
	 * Documentation address (RFC 5737), not a network this suite contacts.
	 */
	protected const CLIENT_IP = '203.0.113.10';

	/** @var list<int> */
	private array $auth_cookie_users = array();

	protected function setUp(): void {
		parent::setUp();

		$_SERVER['REMOTE_ADDR'] = self::CLIENT_IP;
		$this->forget_browser();
		wp_set_current_user( 0 );
		$this->auth_cookie_users = array();
		add_action( 'set_auth_cookie', array( $this, 'record_auth_cookie' ), 10, 4 );

		$this->ensure_schema();
		$this->empty_plugin_tables();
		$this->configure();

		VerifierFake::instance()->reset();
		FireFlyHttpFake::instance()->reset();

		$this->assertInstanceOf( VerifierFake::class, Plugin::instance()->verifier() );
	}

	protected function tearDown(): void {
		$this->forget_browser();
		wp_set_current_user( 0 );
		parent::tearDown();
	}

	/**
	 * @param mixed $cookie
	 * @param mixed $expire
	 * @param mixed $expiration
	 * @param mixed $user_id
	 */
	public function record_auth_cookie( $cookie, $expire, $expiration, $user_id ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- action signature.
		$this->auth_cookie_users[] = (int) $user_id;
	}

	/**
	 * @return list<int>
	 */
	protected function auth_cookie_users(): array {
		return $this->auth_cookie_users;
	}

	protected function reset_auth_cookies(): void {
		$this->auth_cookie_users = array();
	}

	/**
	 * @param array<string, mixed> $overrides
	 */
	protected function configure( array $overrides = array() ): void {
		$settings = array_merge(
			array(
				'enabled'              => true,
				'verifier_auth_header' => 'Bearer integration-test',
				'verifier_url'         => 'https://verifier.example',
				'webhook_secret'       => self::WEBHOOK_SECRET,
				'firefly_url'          => 'https://firefly.example',
				'firefly_namespace'    => 'default',
				'firefly_listener_id'  => (string) CapturedLoginEvent::fixture()['listener'],
				'event_mode'           => Settings::EVENT_MODE_WEBHOOK,
				'linking_policy'       => Settings::LINK_ONLY,
				'default_role'         => 'subscriber',
				'max_pending_per_ip'   => 10,
				'attempt_ttl'          => 180,
				'poll_fallback_after'  => 15,
			),
			$overrides
		);
		update_option( Settings::OPTION, $settings );
		Plugin::instance()->settings()->flush();
	}

	/**
	 * @param array<string, mixed> $params
	 * @param array<string, string> $headers
	 */
	protected function dispatch( string $method, string $route, array $params = array(), array $headers = array(), bool $token = true ): \WP_REST_Response {
		$request = new \WP_REST_Request( $method, '/' . Routes::NAMESPACE . $route );
		if ( $token ) {
			$request->set_header( BrowserController::TOKEN_HEADER, PageToken::create() );
		}
		foreach ( $headers as $name => $value ) {
			$request->set_header( $name, $value );
		}
		if ( in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			$request->set_header( 'Content-Type', 'application/json' );
			$request->set_body( (string) wp_json_encode( $params ) );
		}
		foreach ( $params as $key => $value ) {
			$request->set_param( (string) $key, $value );
		}

		return rest_do_request( $request );
	}

	protected function assert_http( int $status, \WP_REST_Response $response ): void {
		$this->assertSame( $status, $response->get_status(), (string) wp_json_encode( $response->get_data() ) );
	}

	protected function error_code( \WP_REST_Response $response ): string {
		$data = $response->get_data();
		return is_array( $data ) && isset( $data['code'] ) ? (string) $data['code'] : '';
	}

	/**
	 * @return array{data: array<string, mixed>, row: array<string, mixed>}
	 */
	protected function open_attempt(): array {
		$response = $this->dispatch( 'POST', '/initiate' );
		$this->assert_http( 201, $response );
		$data = $response->get_data();
		$this->assertIsArray( $data );
		$row = $this->attempt_row( (string) $data['attempt'] );
		$this->assertNotNull( $row );

		return array(
			'data' => $data,
			'row'  => $row,
		);
	}

	/**
	 * @param array<string, mixed> $row
	 * @return array<string, mixed> The delivery WordPress re-reads.
	 */
	protected function attest( array $row, bool $removed = false ): array {
		$delivery = CapturedLoginEvent::delivery_for( (string) $row['correlation_id'], $removed );
		FireFlyHttpFake::instance()->serve( $delivery );
		$response = $this->dispatch(
			'POST',
			'/firefly/events',
			$delivery,
			array( WebhookController::SECRET_HEADER => self::WEBHOOK_SECRET ),
			false
		);
		$this->assert_http( 204, $response );

		return $delivery;
	}

	protected function complete( string $public_id ): \WP_REST_Response {
		return $this->dispatch( 'POST', '/complete', array( 'attempt' => $public_id ) );
	}

	/**
	 * @return array<string, mixed>|null
	 */
	protected function attempt_row( string $public_id ): ?array {
		global $wpdb;
		$table = Schema::attempts_table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE public_id = %s", $public_id ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return is_array( $row ) ? $row : null;
	}

	protected function attempt_count(): int {
		global $wpdb;
		$table = Schema::attempts_table();

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/**
	 * @param array<string, scalar> $fields
	 */
	protected function backdate( string $public_id, array $fields ): void {
		global $wpdb;
		$wpdb->update( Schema::attempts_table(), $fields, array( 'public_id' => $public_id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	protected function link_subject( int $user_id, ?string $subject = null ): void {
		$subject  = $subject ?? (string) CapturedLoginEvent::fixture()['subject'];
		$settings = Plugin::instance()->settings();
		$hash     = hash_hmac( 'sha256', $subject, $settings->subject_key() );
		$linked   = Plugin::instance()->identities()->link(
			$hash,
			$user_id,
			IdentityRepository::label( $subject, $settings->subject_key() ),
			'did:web:issuer.example'
		);
		$this->assertTrue( $linked );
	}

	protected function subject_hash( ?string $subject = null ): string {
		$subject = $subject ?? (string) CapturedLoginEvent::fixture()['subject'];

		return hash_hmac( 'sha256', $subject, Plugin::instance()->settings()->subject_key() );
	}

	protected function binding_cookie(): string {
		$name = Plugin::instance()->binding()->cookie_name();

		return isset( $_COOKIE[ $name ] ) ? (string) $_COOKIE[ $name ] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- opaque test cookie.
	}

	protected function forget_browser(): void {
		unset( $_COOKIE[ Plugin::instance()->binding()->cookie_name() ] );
	}

	protected function restore_browser( string $secret ): void {
		$_COOKIE[ Plugin::instance()->binding()->cookie_name() ] = $secret;
	}

	/**
	 * The test library rewrites CREATE/DROP TABLE so core tables survive a rollback.
	 * Activation and uninstall have to hit the real plugin tables.
	 */
	protected function use_real_tables(): void {
		remove_filter( 'query', array( $this, '_create_temporary_tables' ) );
		remove_filter( 'query', array( $this, '_drop_temporary_tables' ) );
	}

	private function ensure_schema(): void {
		global $wpdb;
		$attempts = Schema::attempts_table();
		$found    = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $attempts ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		if ( $found !== $attempts || get_option( Schema::VERSION_OPTION ) !== Schema::VERSION ) {
			Schema::install();
		}
	}

	private function empty_plugin_tables(): void {
		global $wpdb;
		$wpdb->query( 'DELETE FROM ' . Schema::attempts_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DELETE FROM ' . Schema::identities_table() ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
	}
}
