#!/bin/sh
# Builds the wallet the FireFly signer is allowed to hold.
#
# The registry owner is never part of that wallet. setup.sh may copy the
# owner keystore into a running signer's memory for setIssuer; this script
# is what removes it from the stored directory, and what a restart uses to
# rebuild the wallet from the attestor key alone.
set -eu

usage() {
	echo "usage: signer-wallet.sh filename|strip|prepare|heartbeat-stale ..." >&2
	exit 2
}

keystore_name() {
	printf '%s' "$1" | tr -d '[:space:]' | sed 's/^0[Xx]//' | tr 'A-F' 'a-f'
}

read_address_file() {
	keystore_name "$(cat "$1")"
}

cmd="${1:-}"
if [ -z "${cmd}" ]; then
	usage
fi
shift

case "${cmd}" in
filename)
	address_file=""
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--address-file)
			address_file="$2"
			shift 2
			;;
		*)
			usage
			;;
		esac
	done
	if [ -z "${address_file}" ] || [ ! -f "${address_file}" ]; then
		echo "address file is missing" >&2
		exit 1
	fi
	read_address_file "${address_file}"
	;;
strip)
	dir=""
	address_file=""
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--dir)
			dir="$2"
			shift 2
			;;
		--address-file)
			address_file="$2"
			shift 2
			;;
		*)
			usage
			;;
		esac
	done
	if [ -z "${dir}" ] || [ -z "${address_file}" ] || [ ! -f "${address_file}" ]; then
		echo "strip needs --dir and --address-file" >&2
		exit 1
	fi
	owner="$(read_address_file "${address_file}")"
	rm -f "${dir}/keystore/${owner}" "${dir}/keystore/${owner}.toml" "${dir}/registry-owner.password"
	;;
prepare)
	attest=""
	dest=""
	signer_file=""
	owner_file=""
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--attest)
			attest="$2"
			shift 2
			;;
		--dest)
			dest="$2"
			shift 2
			;;
		--signer-file)
			signer_file="$2"
			shift 2
			;;
		--owner-file)
			owner_file="$2"
			shift 2
			;;
		*)
			usage
			;;
		esac
	done
	if [ -z "${attest}" ] || [ -z "${dest}" ] || [ -z "${signer_file}" ] || [ -z "${owner_file}" ]; then
		echo "prepare needs --attest, --dest, --signer-file and --owner-file" >&2
		exit 1
	fi
	signer="$(read_address_file "${signer_file}")"
	owner="$(read_address_file "${owner_file}")"
	if [ -z "${signer}" ] || [ -z "${owner}" ] || [ "${signer}" = "${owner}" ]; then
		echo "registry owner must not be the bridge signing key" >&2
		exit 1
	fi
	if [ ! -f "${attest}/keystore/${signer}" ] || [ ! -f "${attest}/keystore/${signer}.toml" ] || [ ! -f "${attest}/password" ]; then
		echo "the attestor keystore is missing" >&2
		exit 1
	fi
	rm -rf "${dest}/keystore" "${dest}/password" "${dest}/registry-owner.password"
	mkdir -p "${dest}/keystore"
	cp "${attest}/keystore/${signer}" "${dest}/keystore/${signer}"
	cp "${attest}/keystore/${signer}.toml" "${dest}/keystore/${signer}.toml"
	cp "${attest}/password" "${dest}/password"
	chmod 644 "${dest}/keystore/${signer}" "${dest}/keystore/${signer}.toml" "${dest}/password"
	;;
heartbeat-stale)
	now="${1:-}"
	beat="${2:-}"
	limit="${3:-20}"
	case "${now}" in
	''|*[!0-9]*)
		echo "heartbeat-stale needs a numeric time" >&2
		exit 2
		;;
	esac
	case "${beat}" in
	''|*[!0-9]*)
		beat=0
		;;
	esac
	case "${limit}" in
	''|*[!0-9]*)
		echo "heartbeat-stale needs a numeric limit" >&2
		exit 2
		;;
	esac
	if [ $((now - beat)) -gt "${limit}" ]; then
		exit 0
	fi
	exit 1
	;;
*)
	usage
	;;
esac
