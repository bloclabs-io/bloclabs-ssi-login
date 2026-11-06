#!/usr/bin/env bash
# One command after a clone: build and start the stack, compile and deploy
# the attestor, install WordPress and print the credential offer.
set -euo pipefail

cd "$(dirname "$0")"

# Git Bash otherwise rewrites /src and /opt into a Windows path.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
	echo "Docker Compose v2 is required (the \"docker compose\" command)." >&2
	exit 1
fi

# Published host ports. demo/.env overrides the defaults. The bind address
# stays 127.0.0.1 in docker-compose.yml; only the port number is configurable.
load_ports() {
	local cleaned name value
	if [[ -f .env ]]; then
		cleaned="$(mktemp)"
		tr -d '\r' < .env > "${cleaned}"
		set -a
		# shellcheck disable=SC1090
		. "${cleaned}"
		set +a
		rm -f "${cleaned}"
	fi
	WORDPRESS_PORT="${WORDPRESS_PORT:-8080}"
	WALLET_WEB_PORT="${WALLET_WEB_PORT:-7106}"
	WALLET_API_PORT="${WALLET_API_PORT:-7006}"
	for name in WORDPRESS_PORT WALLET_WEB_PORT WALLET_API_PORT; do
		value="${!name}"
		if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( 10#${value} < 1 || 10#${value} > 65535 )); then
			echo "${name} must be a TCP port from 1 to 65535." >&2
			exit 1
		fi
	done
	if [[ "${WORDPRESS_PORT}" == "${WALLET_WEB_PORT}" || "${WORDPRESS_PORT}" == "${WALLET_API_PORT}" || "${WALLET_WEB_PORT}" == "${WALLET_API_PORT}" ]]; then
		echo "WORDPRESS_PORT, WALLET_WEB_PORT and WALLET_API_PORT must be different." >&2
		exit 1
	fi
	export WORDPRESS_PORT WALLET_WEB_PORT WALLET_API_PORT
}

load_ports

# A killed setup used to leave the owner keystore in signer/. Delete that
# leftover before any container starts. The registry owner is never loaded
# into FireFly's signer; deploy signs with a signer the bridge cannot reach.
strip_stored_owner_key() {
	if [[ -f runtime/registry-owner.address && -d signer ]]; then
		sh ./bin/signer-wallet.sh strip --dir signer --address-file runtime/registry-owner.address
	fi
}

start_owner_signer() {
	local file attempt cid status
	if [[ ! -f runtime/registry-owner.address ]]; then
		echo "The registry owner address is missing." >&2
		return 1
	fi
	file="$(sh ./bin/signer-wallet.sh filename --address-file runtime/registry-owner.address)"
	if [[ ! -f "registry-owner/keystore/${file}" || ! -f "registry-owner/password" ]]; then
		echo "The registry owner key is missing. Reset with: docker compose down -v && rm -rf runtime signer registry-owner" >&2
		return 1
	fi
	docker compose --profile setup up -d --no-deps --force-recreate owner-signer
	for attempt in $(seq 1 40); do
		cid="$(docker compose --profile setup ps -q owner-signer)"
		if [[ -n "${cid}" ]]; then
			status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "${cid}" 2>/dev/null || true)"
			status="${status//$'\r'/}"
			if [[ "${status}" == "healthy" ]]; then
				return 0
			fi
		fi
		sleep 2
	done
	echo "The registry-owner signer did not become healthy." >&2
	docker compose --profile setup logs owner-signer >&2 || true
	return 1
}

stop_owner_signer() {
	docker compose --profile setup stop owner-signer >/dev/null 2>&1 || true
	docker compose --profile setup rm -f owner-signer >/dev/null 2>&1 || true
}

wait_http() {
	local url="$1"
	local label="$2"
	local expect="${3:-}"
	local attempt code
	for attempt in $(seq 1 90); do
		code="$(docker compose exec -T firefly curl -s -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || true)"
		code="${code//$'\r'/}"
		if [[ -n "${expect}" && "${code}" == "${expect}" ]]; then
			return 0
		fi
		if [[ -z "${expect}" && "${code}" != "000" && -n "${code}" ]]; then
			return 0
		fi
		if [[ "${attempt}" -eq 90 ]]; then
			echo "Timed out waiting for ${label} (last HTTP status: ${code:-none})." >&2
			return 1
		fi
		sleep 2
	done
}

echo "Removing any registry owner key left in the signer directory..."
strip_stored_owner_key

echo "Starting the demo stack..."
docker compose up -d --build

echo "Waiting for generated keys..."
ready=0
for _ in $(seq 1 90); do
	if [[ -f runtime/ready ]]; then
		ready=1
		break
	fi
	sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
	echo "Key generation did not finish." >&2
	docker compose logs keys >&2 || true
	exit 1
fi

echo "Waiting for FireFly..."
wait_http "http://127.0.0.1:5000/api/v1/status" "FireFly" "200"

echo "Waiting for the issuer..."
wait_http "http://issuer.demo/" "the issuer"

echo "Compiling the attestor and the trusted-issuer registry with solc 0.8.28 (Paris)..."
compiled="$(mktemp)"
if ! docker run --rm -v "${PWD}/../contracts:/src:ro" ethereum/solc:0.8.28 \
	--optimize --evm-version paris --combined-json abi,bin \
	/src/SsiLoginAttestor.sol /src/TrustedIssuerRegistry.sol >"${compiled}"; then
	rm -f "${compiled}"
	exit 1
fi
first="$(head -c 1 "${compiled}" | tr -d '[:space:]' || true)"
if [[ "${first}" != "{" ]]; then
	echo "solc did not write JSON. The output starts with:" >&2
	head -c 240 "${compiled}" >&2 || true
	echo >&2
	rm -f "${compiled}"
	exit 1
fi
tr -d '\r' <"${compiled}" > runtime/contract.json
rm -f "${compiled}"

echo "Starting the registry-owner signer on the setup network..."
trap stop_owner_signer EXIT
start_owner_signer

echo "Deploying the attestor and the trusted-issuer registry, then requesting a credential offer..."
docker compose run --rm --no-deps --entrypoint node keys /opt/demo/deploy.mjs

echo "Stopping the registry-owner signer..."
stop_owner_signer
trap - EXIT

echo "Waiting for WordPress..."
wordpress_ready=0
for _ in $(seq 1 90); do
	if docker compose exec -T wordpress sh -c 'test -f /var/www/html/wp-config.php' >/dev/null 2>&1; then
		wordpress_ready=1
		break
	fi
	sleep 2
done
if [[ "${wordpress_ready}" -ne 1 ]]; then
	echo "WordPress did not create wp-config.php." >&2
	docker compose logs wordpress >&2 || true
	exit 1
fi

echo "Installing WordPress and subscribing to FireFly..."
docker compose --profile setup run --rm wpcli

offer="$(tr -d '\r\n' < runtime/offer.url)"
admin="$(tr -d '\r\n' < runtime/wp-admin.password)"

cat <<EOF

The demo is up.

Wallet:     http://127.0.0.1:${WALLET_WEB_PORT}
Wallet API: http://127.0.0.1:${WALLET_API_PORT}
WordPress:  http://127.0.0.1:${WORDPRESS_PORT}
Login:      http://127.0.0.1:${WORDPRESS_PORT}/wp-login.php
Admin user: demo
Admin password: ${admin}

Credential offer for Ada Lovelace (ada@example.com). It lasts a day.
Run ./setup.sh again for a fresh one:

${offer}

1. Open the wallet and register (any email, password of at least 4 characters).
2. Receive: paste the credential offer above.
3. Open the WordPress login page and choose "Log in with a digital credential".
4. Copy the address of "Open wallet on this device". It starts with openid4vp://.
5. In the wallet, Present: paste that address and approve.
6. The site home page greets you as Ada Lovelace.

To start over: docker compose down -v && rm -rf runtime signer registry-owner
EOF
