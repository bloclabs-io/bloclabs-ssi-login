#!/bin/sh
# The signer's stored directory is mounted at /attest. The process signs
# with a wallet under /data, which is a tmpfs rebuilt on every start from
# the attestor key alone. A registry-owner file left in /attest is not
# copied. setup.sh may add that key to /data for setIssuer; if it stops
# refreshing /run/setup-heartbeat, the next check deletes the key and
# restarts ffsigner without it.
set -eu

prepare() {
	/bin/sh /signer-wallet.sh prepare \
		--attest /attest \
		--dest /data \
		--signer-file /runtime/signer.address \
		--owner-file /runtime/registry-owner.address
}

child=0
rescan=0
gen=0

start_signer() {
	gen=$((gen + 1))
	printf '%s\n' "${gen}" > /run/signer-generation
	/usr/bin/ffsigner -f /runtime/ffsigner.yaml &
	child=$!
}

on_usr1() {
	rescan=1
	if [ "${child}" -ne 0 ]; then
		kill "${child}" 2>/dev/null || true
	fi
}

on_term() {
	if [ "${child}" -ne 0 ]; then
		kill "${child}" 2>/dev/null || true
	fi
	exit 0
}

trap on_usr1 USR1
trap on_term TERM INT

prepare
start_signer

while true; do
	if ! kill -0 "${child}" 2>/dev/null; then
		wait "${child}" 2>/dev/null || true
		if [ "${rescan}" -eq 1 ]; then
			rescan=0
		else
			prepare
		fi
		start_signer
	else
		owner="$(/bin/sh /signer-wallet.sh filename --address-file /runtime/registry-owner.address)"
		if [ -f "/data/keystore/${owner}" ]; then
			now="$(date +%s)"
			beat=0
			if [ -f /run/setup-heartbeat ]; then
				beat="$(tr -d '[:space:]' < /run/setup-heartbeat)"
			fi
			if /bin/sh /signer-wallet.sh heartbeat-stale "${now}" "${beat}"; then
				prepare
				kill "${child}" 2>/dev/null || true
				wait "${child}" 2>/dev/null || true
				start_signer
			fi
		fi
	fi
	sleep 2
done
