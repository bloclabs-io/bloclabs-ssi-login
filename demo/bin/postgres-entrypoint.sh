#!/bin/sh
# The database password cannot live in the Compose file (that file is
# committed). It is generated into runtime/ on first start.
set -eu
tr -d '\r' < /runtime/postgres.env > /tmp/postgres.env
set -a
# shellcheck disable=SC1091
. /tmp/postgres.env
set +a
exec docker-entrypoint.sh "$@"
