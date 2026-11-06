#!/bin/sh
# Loads only the registry-owner keystore into this process's tmpfs wallet.
# FireFly's signer does not use this entrypoint.
set -eu
/bin/sh /signer-wallet.sh install-owner \
	--source /owner \
	--dest /data \
	--address-file /runtime/registry-owner.address
exec /usr/bin/ffsigner -f /owner-signer.yaml
