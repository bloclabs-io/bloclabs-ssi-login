<?php
/**
 * The name fields of an auto-provisioned account (#56).
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Identity\UserResolver;
use PHPUnit\Framework\TestCase;

final class UserResolverTest extends TestCase {

	private const LOGIN = 'ssi-d137ea253197';

	public function test_the_name_claim_is_the_display_name(): void {
		$this->assertSame(
			array( 'display_name' => 'Ada Lovelace' ),
			UserResolver::name_fields( array( 'name' => ' Ada Lovelace ' ), self::LOGIN )
		);
	}

	/**
	 * SD-JWT VC identity credentials usually disclose given_name and family_name and no name.
	 */
	public function test_given_and_family_name_make_the_display_first_and_last_name(): void {
		$this->assertSame(
			array(
				'display_name' => 'Ada Lovelace',
				'first_name'   => 'Ada',
				'last_name'    => 'Lovelace',
			),
			UserResolver::name_fields(
				array(
					'given_name'  => 'Ada',
					'family_name' => 'Lovelace',
					'email'       => 'ada@example.com',
				),
				self::LOGIN
			)
		);
	}

	public function test_either_name_alone_is_the_display_name(): void {
		$this->assertSame(
			array(
				'display_name' => 'Lovelace',
				'last_name'    => 'Lovelace',
			),
			UserResolver::name_fields( array( 'family_name' => 'Lovelace' ), self::LOGIN )
		);
		$this->assertSame(
			array(
				'display_name' => 'Ada',
				'first_name'   => 'Ada',
			),
			UserResolver::name_fields( array( 'given_name' => 'Ada' ), self::LOGIN )
		);
	}

	public function test_name_wins_over_given_and_family_name_for_the_display_name(): void {
		$this->assertSame(
			array(
				'display_name' => 'Countess of Lovelace',
				'first_name'   => 'Ada',
				'last_name'    => 'Lovelace',
			),
			UserResolver::name_fields(
				array(
					'name'        => 'Countess of Lovelace',
					'given_name'  => 'Ada',
					'family_name' => 'Lovelace',
				),
				self::LOGIN
			)
		);
	}

	public function test_without_any_name_the_login_is_the_display_name(): void {
		$this->assertSame( array( 'display_name' => self::LOGIN ), UserResolver::name_fields( array(), self::LOGIN ) );
		$this->assertSame( array( 'display_name' => self::LOGIN ), UserResolver::name_fields( array( 'email' => 'ada@example.com' ), self::LOGIN ) );
		$this->assertSame( array( 'display_name' => self::LOGIN ), UserResolver::name_fields( array( 'name' => '   ' ), self::LOGIN ), 'blank is absent' );
	}

	public function test_values_that_are_not_strings_are_ignored(): void {
		$this->assertSame(
			array( 'display_name' => self::LOGIN ),
			UserResolver::name_fields(
				array(
					'name'        => array( 'Ada' ),
					'given_name'  => 42,
					'family_name' => null,
				),
				self::LOGIN
			)
		);
		$this->assertSame(
			array(
				'display_name' => 'Ada',
				'first_name'   => 'Ada',
			),
			UserResolver::name_fields(
				array(
					'name'        => true,
					'given_name'  => 'Ada',
					'family_name' => array( 'Lovelace' ),
				),
				self::LOGIN
			)
		);
	}

	public function test_names_are_plain_text(): void {
		$this->assertSame(
			array(
				'display_name' => 'Ada Lovelace',
				'first_name'   => 'Ada',
				'last_name'    => 'Lovelace',
			),
			UserResolver::name_fields(
				array(
					'given_name'  => '<b>Ada</b> ',
					'family_name' => ' <em>Lovelace</em>',
				),
				self::LOGIN
			)
		);
	}
}
