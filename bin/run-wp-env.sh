#!/usr/bin/env bash
# Runs the WordPress integration suite inside wp-env.
#
# On the host this starts the environment from .wp-env.json and runs this
# script again in the cli container. WordPress 6.6.10 is the core that
# wp-phpunit and the MySQL CI job already use. The suite keeps its own
# wptests_ tables, so it does not drop the site wp-env installed.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ "${1:-}" != "--inside" ]]; then
	if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
		echo "npm run test:wp-env needs Docker, and the daemon has to be running." >&2
		exit 1
	fi
	node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || (major === 22 && minor < 13)) { console.error("Node.js 22.13 or newer is required. This is " + process.versions.node); process.exit(1); }'
	if [[ ! -x "$root/node_modules/.bin/wp-env" ]]; then
		npm install --no-audit --no-fund
	fi
	"$root/node_modules/.bin/wp-env" start
	exec "$root/node_modules/.bin/wp-env" run cli --env-cwd=wp-content/plugins/bloclabs-ssi-login -- bash bin/run-wp-env.sh --inside
fi

if [[ ! -f /var/www/html/wp-settings.php ]]; then
	echo "bin/run-wp-env.sh --inside runs in the wp-env cli container. Use npm run test:wp-env." >&2
	exit 1
fi

composer install --no-interaction --no-progress --prefer-dist
composer install --no-interaction --no-progress --prefer-dist --working-dir=tools/phpunit9

php -r 'require "/var/www/html/wp-includes/version.php"; if (!isset($wp_version) || "6.6.10" !== $wp_version) { fwrite(STDERR, "wp-env is serving WordPress " . ($wp_version ?? "unknown") . "; .wp-env.json and wp-phpunit pin 6.6.10.\n"); exit(1); }'

# wp-env sets the database user, password and name on the cli container.
# It does not set WORDPRESS_DB_HOST; the compose service is named mysql.
: "${WORDPRESS_DB_USER:?wp-env did not set WORDPRESS_DB_USER}"
: "${WORDPRESS_DB_PASSWORD:?wp-env did not set WORDPRESS_DB_PASSWORD}"
: "${WORDPRESS_DB_NAME:?wp-env did not set WORDPRESS_DB_NAME}"
export WP_CORE_DIR=/var/www/html
export WP_TESTS_DB_HOST="${WORDPRESS_DB_HOST:-mysql}"
export WP_TESTS_DB_NAME="$WORDPRESS_DB_NAME"
export WP_TESTS_DB_USER="$WORDPRESS_DB_USER"
export WP_TESTS_DB_PASSWORD="$WORDPRESS_DB_PASSWORD"

echo "Integration suite (single site)"
env -u WP_MULTISITE "$root/tools/phpunit9/vendor/bin/phpunit" -c "$root/phpunit-integration.xml.dist"

echo "Integration suite (multisite)"
WP_MULTISITE=1 "$root/tools/phpunit9/vendor/bin/phpunit" -c "$root/phpunit-integration.xml.dist"
