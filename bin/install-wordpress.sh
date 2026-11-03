#!/usr/bin/env bash
# Downloads the WordPress release the integration suite runs against.
# Already-present files are left alone so a re-run does not hit the network.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="${WP_VERSION:-6.6.10}"
dest="${WP_CORE_DIR:-$root/vendor/wordpress}"

if [[ -f "$dest/wp-settings.php" ]]; then
	exit 0
fi

mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "https://wordpress.org/wordpress-${version}.tar.gz" | tar -xz -C "$tmp"
cp -a "$tmp/wordpress/." "$dest/"
