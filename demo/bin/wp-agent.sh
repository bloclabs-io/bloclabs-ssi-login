#!/bin/bash
# Demo-only WP-CLI steps of ./agent.sh, inside the wpcli container:
#
#   wp-agent.sh link-agent [--user=<login>] [--subject-file=<path>]
#       Links the agent's own subject id (runtime/agent/subject.id, written by
#       `agent.mjs receive`) to an account. Default account: nightly-agent.
#   wp-agent.sh allow-agents --subject=<principal subject id>
#       Turns on "Agents may act for this account" for the account that subject
#       id is linked to, so a credential with acts_for = that id can log in.
#
# The commands themselves are in wordpress/mu-plugins/bloclabs-demo/cli.php.
set -euo pipefail
cd /var/www/html

# As in wp-setup.sh: WP-CLI needs the database settings the WordPress
# container reads from the environment.
tr -d '\r' < /runtime/wordpress.env > /tmp/wordpress.env
set -a
# shellcheck disable=SC1091
. /tmp/wordpress.env
set +a

command="${1:-}"
shift || true

user="nightly-agent"
subject_file="/runtime/agent/subject.id"
subject=""
for arg in "$@"; do
	case "${arg}" in
		--user=*) user="${arg#*=}" ;;
		--subject-file=*) subject_file="${arg#*=}" ;;
		--subject=*) subject="${arg#*=}" ;;
		*)
			echo "wp-agent.sh: unknown option ${arg}" >&2
			exit 2
			;;
	esac
done

case "${command}" in
	link-agent)
		if [[ ! -r "${subject_file}" ]]; then
			echo "${subject_file} is missing: run the agent's receive step first." >&2
			exit 1
		fi
		subject="$(tr -d '\r\n' < "${subject_file}")"
		wp bloclabs-demo link-agent --subject="${subject}" --user="${user}"
		;;
	allow-agents)
		if [[ -z "${subject}" ]]; then
			echo "allow-agents needs --subject=<the principal's subject id>." >&2
			exit 2
		fi
		wp bloclabs-demo allow-agents --subject="${subject}"
		;;
	*)
		echo "usage: wp-agent.sh link-agent [--user=<login>] [--subject-file=<path>] | allow-agents --subject=<id>" >&2
		exit 2
		;;
esac
