<?php
/**
 * Answers FireFly's REST API from the captured event. No network.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration\Support;

final class FireFlyHttpFake {

	private static ?self $instance = null;

	public int $status = 200;

	/** @var array<string, mixed>|null Event body returned by GET /events/{id}. */
	public ?array $delivery = null;

	/** @var list<array<string, mixed>>|null */
	public ?array $blockchain_events = null;

	public int $calls = 0;

	/** @var list<string> */
	public array $urls = array();

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	public function register(): void {
		add_filter( 'pre_http_request', array( $this, 'respond' ), 10, 3 );
	}

	public function reset(): void {
		$this->status            = 200;
		$this->delivery          = null;
		$this->blockchain_events = null;
		$this->calls             = 0;
		$this->urls              = array();
	}

	/**
	 * @param array<string, mixed> $delivery
	 */
	public function serve( array $delivery ): void {
		$this->delivery          = $delivery;
		$chain                   = $delivery['blockchainEvent'] ?? null;
		$this->blockchain_events = is_array( $chain ) ? array( $chain ) : array();
		$this->status            = 200;
	}

	/**
	 * @param mixed                $preempt
	 * @param array<string, mixed> $args
	 * @return mixed
	 */
	public function respond( $preempt, array $args, string $url ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- filter signature.
		if ( ! str_contains( $url, 'firefly.example' ) ) {
			return $preempt;
		}

		++$this->calls;
		$this->urls[] = $url;

		if ( str_contains( $url, '/blockchainevents' ) ) {
			parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $query );
			return $this->json( $this->status, array_slice( $this->blockchain_events ?? array(), (int) ( $query['skip'] ?? 0 ), (int) ( $query['limit'] ?? 50 ) ) );
		}

		if ( str_contains( $url, '/events/' ) ) {
			if ( 200 !== $this->status ) {
				return $this->json( $this->status, array( 'error' => 'not found' ) );
			}
			return $this->json( 200, $this->delivery ?? array() );
		}

		return $this->json( 599, array( 'error' => 'unexpected FireFly request' ) );
	}

	/**
	 * @param array<mixed> $body
	 * @return array<string, mixed>
	 */
	private function json( int $code, array $body ): array {
		return array(
			'headers'  => array(),
			'body'     => (string) wp_json_encode( $body ),
			'response' => array(
				'code'    => $code,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}
}
