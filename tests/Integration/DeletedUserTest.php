<?php
/**
 * A deleted account keeps no credential link.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin\Tests\Integration;

use BlocLabs\SsiLogin\Plugin;

final class DeletedUserTest extends IntegrationTestCase {

	public function test_deleted_user_removes_the_credential_link(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->link_subject( $user_id );
		$hash = $this->subject_hash();
		$this->assertSame( $user_id, Plugin::instance()->identities()->user_id_for( $hash ) );

		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $user_id );

		$this->assertNull( Plugin::instance()->identities()->user_id_for( $hash ) );
		$this->assertFalse( get_userdata( $user_id ) );
	}
}
