#!/usr/bin/env bash
# Runs the WordPress integration suite on PHPUnit 9.
# WordPress 6.6's test library calls PHPUnit\Util\Test::parseTestMethodAnnotations()
# from every test's set_up(), and PHPUnit 10 removed that method. The unit suite
# (composer test) stays on PHPUnit 10 and never loads this runner.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

bash "$root/bin/install-wordpress.sh"

if [[ ! -x "$root/tools/phpunit9/vendor/bin/phpunit" ]]; then
	composer install --no-interaction --no-progress --working-dir="$root/tools/phpunit9"
fi

exec "$root/tools/phpunit9/vendor/bin/phpunit" -c "$root/phpunit-integration.xml.dist" "$@"
