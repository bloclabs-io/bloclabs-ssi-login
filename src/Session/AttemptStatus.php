<?php
/**
 * Lifecycle of one login attempt.
 *
 *   pending ──attested OK──▶ verified ──/complete──▶ consumed
 *      │  └─attested fail──▶ rejected
 *      └──────TTL──────────▶ expired
 *   pending/verified ──error▶ failed
 *
 * Every change goes through AttemptRepository::transition(), which is a
 * compare-and-set on the current status, so a replayed webhook or a double
 * click on /complete can never apply twice.
 *
 * phpcs:disable PHPCompatibility.Variables.ForbiddenThisUseContexts, PHPCompatibility.FunctionDeclarations.NewParamTypeDeclarations.SelfOutsideClassScopeFound -- PHPCompatibility does not parse enums yet.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Session;

enum AttemptStatus: string {

	case Pending  = 'pending';
	case Verified = 'verified';
	case Rejected = 'rejected';
	case Expired  = 'expired';
	case Failed   = 'failed';
	case Consumed = 'consumed';

	public function is_terminal(): bool {
		return match ( $this ) {
			self::Pending, self::Verified => false,
			default => true,
		};
	}

	public function can_transition_to( self $next ): bool {
		return in_array( $next, self::allowed()[ $this->value ] ?? array(), true );
	}

	/**
	 * @return array<string, list<self>>
	 */
	private static function allowed(): array {
		return array(
			self::Pending->value  => array( self::Verified, self::Rejected, self::Expired, self::Failed ),
			self::Verified->value => array( self::Consumed, self::Expired, self::Failed ),
		);
	}

	/**
	 * What the browser may learn. Rejected and failed look the same from outside.
	 */
	public function public_label(): string {
		return match ( $this ) {
			self::Pending  => 'pending',
			self::Verified => 'verified',
			self::Expired  => 'expired',
			self::Consumed => 'consumed',
			default        => 'failed',
		};
	}
}
