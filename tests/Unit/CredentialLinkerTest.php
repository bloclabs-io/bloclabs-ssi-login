<?php
/**
 * Link completion policy without WordPress or a database.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\FireFly\Attestation;
use BlocLabs\SsiLogin\Identity\CredentialLinker;
use BlocLabs\SsiLogin\Identity\IdentityRepository;
use BlocLabs\SsiLogin\Session\Attempt;
use BlocLabs\SsiLogin\Session\AttemptRepository;
use BlocLabs\SsiLogin\Session\AttemptStatus;
use BlocLabs\SsiLogin\Verifier\PresentationResult;
use BlocLabs\SsiLogin\Verifier\VerifierClient;
use PHPUnit\Framework\TestCase;

require_once dirname( __DIR__ ) . '/Stubs/LinkWordPress.php';

final class CredentialLinkerTest extends TestCase {

	private object $database;
	private CredentialLinker $linker;
	private Attempt $attempt;

	protected function setUp(): void {
		$GLOBALS['bloclabs_ssi_link_test_user']                           = 12;
		$GLOBALS['bloclabs_ssi_test_multisite']                           = false;
		$GLOBALS['bloclabs_ssi_test_options']['bloclabs_ssi_subject_key'] = str_repeat( 'a', 64 );
		$this->database  = new class() {
			public string $prefix = 'wp_';
			public string $status = 'verified';
			public ?int $owner    = null;
			public bool $raced    = false;
			public array $deleted = array();

			public function prepare( $query, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
				return $args;
			}
			public function get_var( $query ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
				return $this->owner;
			}
			public function update( $table, $data, $where ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
				if ( $this->status !== $where['status'] ) {
					return 0;
				}
				$this->status = $data['status'];
				return 1;
			}
			public function insert( $table, $data ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
				if ( $this->raced ) {
					$this->owner = 99;
				}
				if ( null !== $this->owner ) {
					return false;
				}
				$this->owner = $data['user_id'];
				return 1;
			}
			public function delete( $table, $where ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
				$this->deleted = $where;
				if ( $where['user_id'] !== $this->owner ) {
					return 0;
				}
				$this->owner = null;
				return 1;
			}
		};
		$GLOBALS['wpdb'] = $this->database; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- isolated database double.
		$result          = new PresentationResult( 'did:example:holder', null, str_repeat( 'b', 64 ), array() );
		$verifier        = $this->createMock( VerifierClient::class );
		$verifier->method( 'fetch_result' )->willReturn( $result );
		$this->linker  = new CredentialLinker( new Settings(), new AttemptRepository(), new IdentityRepository(), $verifier );
		$this->attempt = new Attempt(
			1,
			str_repeat( 'a', 32 ),
			str_repeat( 'c', 64 ),
			str_repeat( 'd', 64 ),
			'nonce',
			str_repeat( 'e', 64 ),
			AttemptStatus::Verified,
			'result',
			null,
			Attestation::subject_commitment( str_repeat( 'c', 64 ), str_repeat( 'e', 64 ), $result->subject_id ),
			$result->presentation_hash,
			time(),
			time() + 180,
			null,
			'link',
			12
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wpdb'], $GLOBALS['bloclabs_ssi_link_test_user'], $GLOBALS['bloclabs_ssi_test_multisite'] );
		unset( $GLOBALS['bloclabs_ssi_test_options']['bloclabs_ssi_subject_key'] );
	}

	public function test_link_attempt_cannot_enter_the_login_finalizer(): void {
		$settings = new Settings();
		$verifier = $this->createMock( VerifierClient::class );
		$verifier->expects( $this->never() )->method( 'fetch_result' );
		$finalizer = new \BlocLabs\SsiLogin\Login\LoginFinalizer(
			new AttemptRepository(),
			new \BlocLabs\SsiLogin\Login\LoginChecks( new AttemptRepository(), $verifier ),
			new \BlocLabs\SsiLogin\Identity\UserResolver( $settings, new IdentityRepository() ),
			new \BlocLabs\SsiLogin\Session\BrowserBinding( $settings )
		);
		$this->assertSame( 'bloclabs_ssi_not_verified', $finalizer->finalize( $this->attempt )->get_error_code() );
		$this->assertSame( 'verified', $this->database->status );
	}

	public function test_link_is_single_use_even_after_unlink(): void {
		$this->assertTrue( $this->linker->complete( $this->attempt ) );
		$this->assertSame( 12, $this->database->owner );
		$this->assertSame( 'consumed', $this->database->status );
		$this->assertTrue( ( new IdentityRepository() )->unlink_owned( 1, 12 ) );
		$this->assertSame( 'bloclabs_ssi_already_used', $this->linker->complete( $this->attempt )->get_error_code() );
		$this->assertNull( $this->database->owner );
	}

	public function test_relink_and_foreign_links_are_refused(): void {
		foreach ( array( 12, 99 ) as $owner ) {
			$this->database->status = 'verified';
			$this->database->owner  = $owner;
			$this->assertSame( 'bloclabs_ssi_already_linked', $this->linker->complete( $this->attempt )->get_error_code() );
			$this->assertSame( $owner, $this->database->owner );
		}
	}

	public function test_concurrent_subject_link_does_not_overwrite_the_winner(): void {
		$this->database->raced = true;
		$this->assertSame( 'bloclabs_ssi_already_linked', $this->linker->complete( $this->attempt )->get_error_code() );
		$this->assertSame( 99, $this->database->owner );
	}

	public function test_switched_account_cannot_link_or_unlink(): void {
		$GLOBALS['bloclabs_ssi_link_test_user'] = 99;
		$this->assertSame( 'bloclabs_ssi_profile_auth', $this->linker->complete( $this->attempt )->get_error_code() );
		$this->assertSame( 'verified', $this->database->status );
		$this->database->owner = 12;
		$this->assertFalse( ( new IdentityRepository() )->unlink_owned( 1, 99 ) );
		$this->assertSame(
			array(
				'id'      => 1,
				'user_id' => 99,
			),
			$this->database->deleted
		);
	}
}
