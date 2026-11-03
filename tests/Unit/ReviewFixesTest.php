<?php
/**
 * Regression tests for findings of the PR #2 review (#4).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Rest\PageToken;
use BlocLabs\SsiLogin\Verifier\PresentationOffer;
use PHPUnit\Framework\TestCase;

final class ReviewFixesTest extends TestCase {

	protected function tearDown(): void {
		unset( $GLOBALS['bloclabs_ssi_test_tick'] );
	}

	public function test_page_token_is_valid_for_this_and_the_previous_tick_only(): void {
		$GLOBALS['bloclabs_ssi_test_tick'] = 500;
		$token                             = PageToken::create();

		$this->assertTrue( PageToken::verify( $token ) );

		$GLOBALS['bloclabs_ssi_test_tick'] = 501;
		$this->assertTrue( PageToken::verify( $token ), 'still valid in the next half-day' );

		$GLOBALS['bloclabs_ssi_test_tick'] = 502;
		$this->assertFalse( PageToken::verify( $token ), 'expired after two ticks' );

		$this->assertFalse( PageToken::verify( '' ) );
		$this->assertFalse( PageToken::verify( 'abcdefghij' ) );
	}

	public function test_identity_label_never_contains_the_subject(): void {
		$did   = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
		$label = IdentityRepository::label( $did );

		$this->assertMatchesRegularExpression( '/^did:key #[0-9a-f]{8}$/', $label );
		$this->assertStringNotContainsString( 'z6Mk', $label );
		$this->assertMatchesRegularExpression( '/^credential #[0-9a-f]{8}$/', IdentityRepository::label( 'https://issuer.example|1234' ) );
	}

	public function test_wallet_schemes_are_normalised(): void {
		$this->assertSame( array( 'openid4vp', 'https' ), PresentationOffer::wallet_schemes() );
	}
}
