<?php
/**
 * Activation and deactivation. Uninstall lives in uninstall.php.
 *
 * @package BlocLabs\SsiLogin
 */

declare(strict_types=1);

namespace BlocLabs\SsiLogin;

use BlocLabs\SsiLogin\Config\Settings;
use BlocLabs\SsiLogin\Cron\PurgeExpired;
use BlocLabs\SsiLogin\Database\Schema;

final class Lifecycle {

	public static function activate(): void {
		Schema::install();
		Settings::ensure_subject_key();
		PurgeExpired::schedule();
	}

	public static function deactivate(): void {
		PurgeExpired::unschedule();
	}
}
