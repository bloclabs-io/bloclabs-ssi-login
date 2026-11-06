#!/bin/sh
# First start only. Passwords come from the environment the entrypoint
# wrapper loaded; they are hex, so they need no SQL quoting beyond the
# single quotes below.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOF
CREATE USER firefly WITH PASSWORD '${FIREFLY_DB_PASSWORD}';
CREATE DATABASE firefly OWNER firefly;
CREATE USER wallet WITH PASSWORD '${WALLET_DB_PASSWORD}';
CREATE DATABASE wallet OWNER wallet;
EOF
