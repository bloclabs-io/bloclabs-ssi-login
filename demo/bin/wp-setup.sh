#!/bin/bash
# Runs once per ./setup.sh, inside the wpcli container. Idempotent:
# core install is skipped when WordPress is already installed, config
# constants are written again, and subscribe upserts the webhook.
set -euo pipefail
cd /var/www/html

# The image's wp-config.php reads WORDPRESS_DB_* from the environment on
# every request. The WordPress container loads them; this one must too,
# or WP-CLI talks to a host named mysql with the image's placeholder password.
tr -d '\r' < /runtime/wordpress.env > /tmp/wordpress.env
set -a
# shellcheck disable=SC1091
. /tmp/wordpress.env
set +a

strip() { tr -d '\r\n'; }

if [[ ! -f /var/www/html/wp-config.php ]]; then
	echo "wp-config.php does not exist yet." >&2
	exit 1
fi

admin_pw="$(strip < /runtime/wp-admin.password)"
webhook="$(strip < /runtime/webhook.secret)"
token="$(strip < /runtime/bridge.token)"
subject="$(strip < /runtime/subject.key)"
listener="$(php -r 'echo json_decode(str_replace("\r", "", file_get_contents("/runtime/deployment.json")))->listenerId;')"
address="$(php -r 'echo json_decode(str_replace("\r", "", file_get_contents("/runtime/deployment.json")))->address;')"

if [[ -z "${listener}" || -z "${address}" ]]; then
	echo "deployment.json has no listener id or contract address." >&2
	exit 1
fi

public_url="${WORDPRESS_PUBLIC_URL:-http://127.0.0.1:8080}"
public_url="${public_url//$'\r'/}"
if [[ ! "${public_url}" =~ ^http://127\.0\.0\.1:[0-9]{1,5}$ ]]; then
	echo "WORDPRESS_PUBLIC_URL must be http://127.0.0.1:<port>." >&2
	exit 1
fi

if ! wp core is-installed >/dev/null 2>&1; then
	wp core install \
		--url="${public_url}" \
		--title="blocLabs" \
		--admin_user="demo" \
		--admin_password="${admin_pw}" \
		--admin_email="demo@example.com" \
		--skip-email
fi

wp option update home "${public_url}"
wp option update siteurl "${public_url}"
wp option update blogname "blocLabs"
wp option update blogdescription "Sign in with a credential"
wp option update blog_public 0

wp config set BLOCLABS_SSI_ENABLED true --raw
wp config set BLOCLABS_SSI_FIREFLY_URL "http://firefly:5000"
wp config set BLOCLABS_SSI_FIREFLY_NAMESPACE "default"
wp config set BLOCLABS_SSI_FIREFLY_LISTENER_ID "${listener}"
wp config set BLOCLABS_SSI_ATTESTOR_ADDRESS "${address}"
wp config set BLOCLABS_SSI_WEBHOOK_SECRET "${webhook}"
wp config set BLOCLABS_SSI_VERIFIER_URL "http://bridge:8090"
wp config set BLOCLABS_SSI_VERIFIER_AUTH_HEADER "Bearer ${token}"
wp config set BLOCLABS_SSI_LINKING_POLICY "auto_provision"
wp config set BLOCLABS_SSI_CREDENTIAL_QUERY "default"
wp config set BLOCLABS_SSI_SUBJECT_KEY "${subject}"

wp plugin activate bloclabs-ssi-login
wp bloclabs-ssi subscribe --webhook-url="http://wordpress/wp-json/bloclabs-ssi/v1/firefly/events"
