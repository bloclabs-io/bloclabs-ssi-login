<?php
/**
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Unit;

use BlocLabs\SsiLogin\Session\AttemptStatus as S;
use PHPUnit\Framework\TestCase;

final class AttemptStatusTest extends TestCase {

	public function test_happy_path(): void {
		$this->assertTrue( S::Pending->can_transition_to( S::Verified ) );
		$this->assertTrue( S::Verified->can_transition_to( S::Consumed ) );
	}

	public function test_a_consumed_attempt_never_changes_again(): void {
		foreach ( S::cases() as $next ) {
			$this->assertFalse( S::Consumed->can_transition_to( $next ), $next->value );
		}
	}

	public function test_pending_cannot_skip_to_consumed(): void {
		$this->assertFalse( S::Pending->can_transition_to( S::Consumed ) );
	}

	public function test_rejected_cannot_be_revived_by_a_later_event(): void {
		$this->assertFalse( S::Rejected->can_transition_to( S::Verified ) );
		$this->assertFalse( S::Expired->can_transition_to( S::Verified ) );
	}

	public function test_terminal_states(): void {
		$this->assertFalse( S::Pending->is_terminal() );
		$this->assertFalse( S::Verified->is_terminal() );
		$this->assertTrue( S::Consumed->is_terminal() );
		$this->assertTrue( S::Rejected->is_terminal() );
	}

	public function test_rejected_and_failed_look_the_same_from_outside(): void {
		$this->assertSame( 'failed', S::Rejected->public_label() );
		$this->assertSame( 'failed', S::Failed->public_label() );
	}
}
