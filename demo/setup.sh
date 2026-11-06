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

owner_loaded=0
heartbeat_pid=0

owner_keystore_name() {
	sh ./bin/signer-wallet.sh filename --address-file runtime/registry-owner.address
}

# A killed setup used to leave the owner keystore in signer/, and the next
# start loaded it. Delete that leftover before any container starts, and
# never copy it back: the running signer keeps its wallet on a tmpfs.
strip_stored_owner_key() {
	if [[ -f runtime/registry-owner.address && -d signer ]]; then
		sh ./bin/signer-wallet.sh strip --dir signer --address-file runtime/registry-owner.address
	fi
}

start_heartbeat() {
	stop_heartbeat
	docker compose exec -T ethsigner /bin/sh -c 'date +%s > /run/setup-heartbeat'
	local parent=$$
	# The refresh loop exits when this script's process is gone, including
	# kill -9, because it watches the parent pid rather than a trap.
	(
		while kill -0 "${parent}" 2>/dev/null; do
			docker compose exec -T ethsigner /bin/sh -c 'date +%s > /run/setup-heartbeat' >/dev/null 2>&1 || true
			sleep 5
		done
	) &
	heartbeat_pid=$!
}

stop_heartbeat() {
	if [[ "${heartbeat_pid}" -ne 0 ]]; then
		kill "${heartbeat_pid}" 2>/dev/null || true
		wait "${heartbeat_pid}" 2>/dev/null || true
		heartbeat_pid=0
	fi
}

rescan_signer() {
	local before now attempt code
	before="$(docker compose exec -T ethsigner cat /run/signer-generation | tr -d '[:space:]')"
	docker compose exec -T ethsigner /bin/sh -c 'kill -USR1 1'
	for attempt in $(seq 1 40); do
		now="$(docker compose exec -T ethsigner cat /run/signer-generation 2>/dev/null | tr -d '[:space:]' || true)"
		code="$(docker compose exec -T ethsigner curl -sf -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' http://127.0.0.1:8545/ 2>/dev/null || true)"
		code="${code//$'\r'/}"
		now="${now//$'\r'/}"
		if [[ -n "${now}" && "${now}" != "${before}" && "${code}" == "200" ]]; then
			return 0
		fi
		sleep 1
	done
	echo "The signer did not reload." >&2
	docker compose logs ethsigner >&2 || true
	return 1
}

# Copy the owner keystore into the running signer's tmpfs, not into signer/.
# The entrypoint drops it if this script stops refreshing the heartbeat.
load_registry_owner() {
	local file
	file="$(owner_keystore_name)"
	if [[ ! -f "registry-owner/keystore/${file}" || ! -f "registry-owner/keystore/${file}.toml" || ! -f "registry-owner/password" ]]; then
		echo "The registry owner key is missing. Reset with: docker compose down -v && rm -rf runtime signer registry-owner" >&2
		return 1
	fi
	start_heartbeat
	owner_loaded=1
	docker compose cp "registry-owner/keystore/${file}" "ethsigner:/data/keystore/${file}"
	docker compose cp "registry-owner/keystore/${file}.toml" "ethsigner:/data/keystore/${file}.toml"
	docker compose cp "registry-owner/password" "ethsigner:/data/registry-owner.password"
	docker compose exec -T ethsigner /bin/sh -c "chmod 644 '/data/keystore/${file}' '/data/keystore/${file}.toml' /data/registry-owner.password"
	rescan_signer
}

unload_registry_owner() {
	local file
	stop_heartbeat
	if [[ "${owner_loaded}" -ne 1 ]]; then
		return 0
	fi
	file="$(owner_keystore_name)"
	owner_loaded=0
	strip_stored_owner_key
	docker compose exec -T ethsigner /bin/sh -c "rm -f '/data/keystore/${file}' '/data/keystore/${file}.toml' /data/registry-owner.password" || true
	rescan_signer || true
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

echo "Loading the registry owner into the signer..."
trap unload_registry_owner EXIT
load_registry_owner

echo "Deploying the attestor and the trusted-issuer registry, then requesting a credential offer..."
docker compose run --rm --no-deps --entrypoint node keys /opt/demo/deploy.mjs

echo "Removing the registry owner from the signer..."
unload_registry_owner
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

Wallet:     http://127.0.0.1:7106
WordPress:  http://127.0.0.1:8080
Login:      http://127.0.0.1:8080/wp-login.php
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
