#!/bin/sh
set -eu
tr -d '\r' < /runtime/wordpress.env > /tmp/wordpress.env
set -a
# shellcheck disable=SC1091
. /tmp/wordpress.env
set +a
exec docker-entrypoint.sh "$@"
