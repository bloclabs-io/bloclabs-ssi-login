<?php
/**
 * "Agents may act for this account": the per-user opt-in that a delegated
 * token needs (ADR 0007 §3 step 4 and §6).
 *
 * Off by default. Stored as user meta under the site's table prefix, like
 * capabilities, so on multisite an account opts in per site, where its
 * tokens and identity links live. The profile screen (6/7) sets it and
 * revokes every delegated token when it is turned off.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Identity;

final class AgentDelegation {

	public const META = 'bloclabs_ssi_agents_allowed';

	public static function meta_key(): string {
		global $wpdb;
		return $wpdb->get_blog_prefix() . self::META;
	}

	public static function allowed( int $user_id ): bool {
		return '1' === (string) get_user_meta( $user_id, self::meta_key(), true );
	}

	public static function allow( int $user_id, bool $allowed ): void {
		if ( $allowed ) {
			update_user_meta( $user_id, self::meta_key(), '1' );
			return;
		}
		delete_user_meta( $user_id, self::meta_key() );
	}
}
