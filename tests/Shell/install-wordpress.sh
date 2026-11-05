#!/usr/bin/env bash
# No network: exercise download, cache hit, release switch and failed download.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/archive/wordpress"
printf '<?php // fixture\n' > "$fixture/archive/wordpress/wp-settings.php"
cat > "$fixture/bin/curl" <<'CURL'
#!/usr/bin/env bash
[[ -z "${FAIL_DOWNLOAD:-}" ]] || exit 22
printf '%s\n' "$*" >> "$FIXTURE/calls"
tar -cz -C "$FIXTURE/archive" wordpress
CURL
chmod +x "$fixture/bin/curl"
export FIXTURE="$fixture" PATH="$fixture/bin:$PATH" WP_CORE_DIR="$fixture/core"
WP_VERSION=6.6.10 bash "$root/bin/install-wordpress.sh"
WP_VERSION=6.6.10 bash "$root/bin/install-wordpress.sh"
[[ "$(wc -l < "$fixture/calls")" == 1 ]]
touch "$WP_CORE_DIR/old-release-only.php"
WP_VERSION=6.7.2 bash "$root/bin/install-wordpress.sh"
[[ "$(cat "$WP_CORE_DIR/.ssi-test-core-version")" == 6.7.2 ]]
[[ ! -e "$WP_CORE_DIR/old-release-only.php" ]]
[[ "$(wc -l < "$fixture/calls")" == 2 ]]
if FAIL_DOWNLOAD=1 WP_VERSION=6.6.10 bash "$root/bin/install-wordpress.sh" 2>/dev/null; then
	exit 1
fi
[[ "$(cat "$WP_CORE_DIR/.ssi-test-core-version")" == 6.7.2 ]]
echo 'PASS version-aware core installation'
