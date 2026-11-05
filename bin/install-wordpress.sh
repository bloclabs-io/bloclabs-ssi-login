#!/usr/bin/env bash
# Downloads the requested WordPress release into the integration-test core directory.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="${WP_VERSION:-6.6.10}"
dest="${WP_CORE_DIR:-$root/vendor/wordpress}"
[[ "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo 'WP_VERSION must be a release number' >&2; exit 1; }

if [[ -f "$dest/wp-settings.php" && -f "$dest/.ssi-test-core-version" ]] && [[ "$(cat "$dest/.ssi-test-core-version")" == "$version" ]]; then
	exit 0
fi

mkdir -p "$(dirname "$dest")"
tmp="$(mktemp -d "$(dirname "$dest")/.ssi-core.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "https://wordpress.org/wordpress-${version}.tar.gz" | tar -xz -C "$tmp"
[[ -f "$tmp/wordpress/wp-settings.php" ]]
printf '%s\n' "$version" > "$tmp/wordpress/.ssi-test-core-version"
# Replace only after a complete download. Stale files from the previous release
# must not survive a downgrade. WP_CORE_DIR is a disposable test-core directory.
if [[ -e "$dest" ]]; then
	mv "$dest" "$tmp/previous"
fi
if ! mv "$tmp/wordpress" "$dest"; then
	[[ ! -e "$tmp/previous" ]] || mv "$tmp/previous" "$dest"
	exit 1
fi
