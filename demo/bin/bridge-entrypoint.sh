#!/bin/sh
# The bridge reads its configuration from the environment. The values are
# files under /runtime so they are never baked into an image layer.
set -eu
cd /app

strip() {
	tr -d '\r\n'
}

BRIDGE_AUTH_TOKEN="$(strip < /runtime/bridge.token)"
BRIDGE_QUERIES="$(tr -d '\r' < /runtime/bridge.queries.json)"
FIREFLY_SIGNING_KEY="$(strip < /runtime/signer.address)"
export BRIDGE_AUTH_TOKEN BRIDGE_QUERIES FIREFLY_SIGNING_KEY
export BRIDGE_PORT=8090
export BRIDGE_CALLBACK_URL=http://bridge:8090/v1/verifier-callbacks
export VERIFIER_URL=http://verifier:7004
export FIREFLY_URL=http://firefly:5000
export FIREFLY_NAMESPACE=default
export FIREFLY_API_NAME=ssi-login-attestor
export BRIDGE_LOG_LEVEL=info

exec node dist/src/main.js
