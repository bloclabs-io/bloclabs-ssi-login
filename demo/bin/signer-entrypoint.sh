#!/bin/sh
# FireFly's signer. The stored directory is mounted at /attest. The process
# signs with a tmpfs wallet that contains only the attestor key, so a
# registry-owner file left in the stored directory is not loaded.
set -eu
/bin/sh /signer-wallet.sh prepare \
	--attest /attest \
	--dest /data \
	--signer-file /runtime/signer.address \
	--owner-file /runtime/registry-owner.address
exec /usr/bin/ffsigner -f /runtime/ffsigner.yaml
