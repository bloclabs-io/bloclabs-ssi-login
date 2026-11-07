#!/usr/bin/env bash
# The agent login, end to end, on the demo stack that ./setup.sh started.
# No browser anywhere (ADR 0007, issue #64): an agent credential is issued to
# the agent's key, the agent's subject id is linked to an account, the agent
# presents the credential to the verifier, gets an application token from
# WordPress, calls the REST API with it and revokes it.
#
#   ./agent.sh                     the agent's own key, linked to the
#                                  nightly-agent account (an author)
#   ./agent.sh --acts-for <id>     a delegated credential: the agent acts for
#                                  the account that subject id is linked to
#                                  (Ada's wallet DID, after she logged in once)
#   ./agent.sh --scope read        the scope to ask for (default read,content)
#   ./agent.sh --keep              leave the token in place for more calls
#
# The agent's key, credential and token live in runtime/agent/ (gitignored).
# Run `docker compose --profile agent run --rm agent help` for the client itself.
set -euo pipefail

cd "$(dirname "$0")"

# Git Bash otherwise rewrites /opt into a Windows path.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

usage() {
	sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

acts_for=""
scope="read,content"
keep=0
while (($#)); do
	case "$1" in
		--acts-for) acts_for="${2:-}"; shift 2 ;;
		--acts-for=*) acts_for="${1#*=}"; shift ;;
		--scope) scope="${2:-}"; shift 2 ;;
		--scope=*) scope="${1#*=}"; shift ;;
		--keep) keep=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*)
			echo "agent.sh: unknown option $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
	echo "Docker Compose v2 is required (the \"docker compose\" command)." >&2
	exit 1
fi
if [[ ! -f runtime/ready || ! -f runtime/deployment.json ]]; then
	echo "The demo stack is not set up. Run ./setup.sh first." >&2
	exit 1
fi

agent() {
	docker compose --profile agent run --rm agent "$@"
}

wpcli() {
	docker compose --profile setup run --rm --entrypoint bash wpcli /opt/demo/wp-agent.sh "$@"
}

say() {
	printf '\n%s\n' "$1"
}

say "Does this WordPress have the agent routes? (OPTIONS agent/initiate, nothing is opened)"
if ! agent check http://wordpress; then
	cat >&2 <<'EOF'

The plugin mounted in this stack has no agent routes, so the agent login cannot run here.
Agent login needs ADR 0007 parts 2 to 4 (schema 5, the agent routes, token issuance and
bearer authentication) in the plugin, and BLOCLABS_SSI_AGENT_LOGIN_ENABLED on, which
./setup.sh sets. Nothing was issued or linked.
EOF
	exit 1
fi

say "Requesting an agent credential offer from the issuer${acts_for:+ (acting for ${acts_for})}..."
docker compose run --rm --no-deps -e "ACTS_FOR=${acts_for}" --entrypoint node keys /opt/demo/agent-offer.mjs
offer="$(tr -d '\r\n' < runtime/agent-offer.url)"

say "The agent's key (generated once, kept in runtime/agent/)..."
agent keygen

say "Receiving the credential (OpenID4VCI, pre-authorized code)..."
agent receive "${offer}"

if [[ -z "${acts_for}" ]]; then
	say "Linking the agent's subject id to the nightly-agent account..."
	wpcli link-agent --user=nightly-agent
else
	say "Allowing agents to act for the account linked to ${acts_for}..."
	wpcli allow-agents --subject="${acts_for}"
fi

say "Logging in: presenting the credential, waiting for the chain, taking the token..."
agent login http://wordpress --scope "${scope}"

say "Who does WordPress say the agent is? (GET wp/v2/users/me with the token)"
agent call wp/v2/users/me

say "Saving a draft post with the token (POST wp/v2/posts)..."
if ! agent call wp/v2/posts --data '{"title":"Nightly report","content":"Written by an agent that logged in with a credential.","status":"draft"}'; then
	echo "Refused: the token's scope, or the account's role, does not allow it. A delegated agent can do no more than its principal."
fi

if (( keep )); then
	say "The token stays in runtime/agent/token.json. More calls: docker compose --profile agent run --rm agent call <path>"
	echo "Revoke it with: docker compose --profile agent run --rm agent logout"
else
	say "Revoking the token (DELETE agent/token)..."
	agent logout
fi
