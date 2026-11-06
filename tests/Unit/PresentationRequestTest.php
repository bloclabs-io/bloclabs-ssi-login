<?php
/**
 * What WordPress sends the bridge for a presentation request.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Verifier\PresentationRequest;
use PHPUnit\Framework\TestCase;

final class PresentationRequestTest extends TestCase {

	private const CORRELATION = '3575e334c14dcc31670ded8ad7c600007ccd69a694c8251151b51c8780b97fea';
	private const SECRET      = 'b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1';

	/**
	 * The return URL travels only when WordPress has one (#96): a bridge written
	 * against the earlier contract sees the same request as before.
	 */
	public function test_the_return_url_travels_only_when_set(): void {
		$expected = array(
			'correlation_id'  => self::CORRELATION,
			'nonce'           => 'wp-nonce-q2F8kZ0',
			'blinding_secret' => self::SECRET,
			'query'           => 'default',
			'expires_at'      => '2026-11-06T19:00:00Z',
		);
		$expires  = (int) strtotime( '2026-11-06T19:00:00Z' );

		$without = new PresentationRequest( self::CORRELATION, 'wp-nonce-q2F8kZ0', self::SECRET, 'default', $expires );
		$this->assertSame( $expected, $without->to_array() );
		$this->assertNull( $without->return_url );

		$empty = new PresentationRequest( self::CORRELATION, 'wp-nonce-q2F8kZ0', self::SECRET, 'default', $expires, '' );
		$this->assertSame( $expected, $empty->to_array() );

		$return = 'https://login.example/wp-login.php?redirect_to=https%3A%2F%2Flogin.example%2Fwp-admin%2F&bloclabs_ssi_attempt=' . str_repeat( 'c', 32 );
		$with   = new PresentationRequest( self::CORRELATION, 'wp-nonce-q2F8kZ0', self::SECRET, 'default', $expires, $return );
		$this->assertSame( $expected + array( 'return_url' => $return ), $with->to_array() );
	}
}
