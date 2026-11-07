# blocLabs SSI Login agent

The reference agent for [ADR 0007](../../docs/adr/0007-agent-login.md): a program that logs in to a WordPress
site with a Verifiable Credential and no browser, and gets an application token. It is what an agent framework
would embed, written plainly enough to read in one sitting: Node 22, no dependencies, the platform's `crypto`,
`fetch` and `util`.

```text
agent.mjs keygen                      make the agent's key (once)
agent.mjs receive <offer>             take the agent credential from an issuer (OpenID4VCI)
agent.mjs check <site>                does this site have the agent routes? (no attempt is opened)
agent.mjs login <site> [--scope …]    present it (OpenID4VP), get a token
agent.mjs call <path> [--method …]    call the REST API with the token
agent.mjs logout                      revoke the token
agent.mjs whoami [--json]             what the agent is and holds
```

Everything the agent keeps lives under `AGENT_HOME` (default `.agent` in the current directory): `agent-key.jwk`
(a P-256 private key, `0600`), `credential.sd-jwt`, `subject.id` (the public identifier the credential binds, what a
site links to an account) and `token.json`. Nothing here is ever committed.

## What a login is

1. `POST /wp-json/bloclabs-ssi/v1/agent/initiate` with the scope the agent wants. WordPress answers with an attempt,
   a 256-bit attempt secret and a wallet URL.
2. The agent fetches the OpenID4VP request object behind that wallet URL's `request_uri` and checks who is asking
   before it discloses anything (see below).
3. It picks the disclosures the request's DCQL query names, and no others, and signs a key-binding JWT over them
   with the verifier's nonce and client id as `aud`.
4. It posts the presentation to the verifier's `response_uri` (`direct_post`).
5. It polls `POST /agent/token` with the attempt secret in the `X-Bloclabs-Ssi-Attempt` header. 409 means the chain
   has not spoken yet; 200 carries the token, once.

The token is `bssi_` and 43 characters. It goes in `Authorization: Bearer` on `/wp-json/` requests, over HTTPS, and
nowhere else. `call` sends it; `logout` revokes it with `DELETE /agent/token` and forgets it.

## Who is asking

The agent presents only to the wallet URL its own initiate call returned. There is no way to hand it another one:
that is the defence against threat A2 (a prompt-injected wallet URL that would log an attacker's attempt in). Before
it presents, `checkVerifier` requires that the request's `client_id` is the one the wallet URL named and, when the
operator pinned one with `--verifier` (or `AGENT_VERIFIER`), that one; that a `redirect_uri:` id names exactly the
`response_uri` (also in the pre-1.0 form, a bare URI with `client_id_scheme`); that an `x509_san_dns:` or
`x509_hash:` id comes in a signed request (`oauth-authz-req+jwt`) whose `x5c` leaf carries that DNS name or hash and
verifies the signature, and that the `response_uri` is on that host. A client id of any other scheme is accepted
only when it is exactly the pinned one. Encrypted responses (`direct_post.jwt`) are not supported.

## Receiving the credential

`receive` takes a credential offer as the issuer prints it: an `openid-credential-offer://` (or `haip://`) URL with
`credential_offer_uri` or `credential_offer`, a bare `https://` URL, or the offer JSON. It supports the
pre-authorized code grant only. It reads the issuer metadata (`/.well-known/openid-credential-issuer`, with the
suffix between host and path as OpenID4VCI 1.0 §11.2.2 puts it, then the plain form), takes a nonce from the nonce
endpoint when the issuer has one (1.0) or from the token answer (draft 13), proves possession of its key with an
`openid4vci-proof+jwt` naming the key as `did:jwk` (`--proof-key jwk` embeds the JWK instead), and asks for the
credential in the 1.0 shape (`credential_configuration_id`, `proofs`), falling back to the draft-13 one on a 400.
An offer that needs a transaction code takes it with `--tx-code`. Deferred issuance is reported, not polled.

## On the demo stack

[`../agent.sh`](../agent.sh) runs the whole login against the stack `../setup.sh` started, through the `agent`
Compose service (profile `agent`, `AGENT_HOME=/runtime/agent`):

```bash
cd demo
./agent.sh                      # the agent's own key, linked to the nightly-agent account
./agent.sh --acts-for <DID>     # a delegated credential: the agent acts for the account that DID logged in to
./agent.sh --scope read         # ask for less
./agent.sh --keep               # leave the token for more calls
docker compose --profile agent run --rm agent call wp/v2/posts   # one of them
```

Without `--acts-for`, the credential is the agent's own (`acts_for` empty) and the demo links the agent's
`subject.id` to the `nightly-agent` account, an author, with a demo-only WP-CLI command that stands in for *Link a
credential* on the profile screen. The token then logs in as that account within its role: `wp/v2/users/me`
answers, a draft post is saved with the `content` scope, `wp/v2/settings` is refused.

With `--acts-for`, the issuer puts that subject id in the credential. It is the DID of the wallet key Ada logged in
with (the wallet shows it under DIDs); she has to have logged in once so that her account exists, and the demo turns
on *Agents may act for this account* for it, which on a real site she does herself. The token then acts as Ada.
Ada is a subscriber, so the draft is refused: a delegated agent can do no more than its principal.

The demo runs on plain HTTP, so WordPress is told `WP_ENVIRONMENT_TYPE=local`, the condition under which a token
is accepted without TLS (the rule core applies to Application Passwords).

## Running it elsewhere

```bash
export AGENT_HOME=/var/lib/my-agent
node agent.mjs keygen
node agent.mjs receive 'openid-credential-offer://…'
node agent.mjs login https://example.org --scope read,content --verifier x509_san_dns:verifier.example.org
node agent.mjs call wp/v2/users/me
node agent.mjs logout
```

`--json` prints machine-readable output and nothing else; the token is masked unless `--show-token`. Exit codes: 0,
1 for a failure, 2 for a usage error, 3 when `call` got an HTTP error. Colour (blocLabs orange for the accent) only on
a terminal and never with `NO_COLOR` set.

## Tests

```bash
npm test
```

The suites run the client against loopback stand-ins for the three services it talks to: a walt.id-shaped issuer
(1.0 and draft-13 shapes, `cnf` as `kid` or `jwk`), a verifier that checks the key-binding JWT the way a verifier
must (unsigned `redirect_uri:` requests and signed `x509_san_dns:` ones with a self-signed certificate from
`openssl`), and WordPress with the agent routes. They cover the SD-JWT holder side (selective disclosure, nested
claims, `sd_hash`), the verifier checks above, the end-to-end login with pending polls, scope ceilings, delegation,
revocation, the vp_token string form, and the CLI from no key to a revoked token.

## Limitations

- One credential, one key, one token at a time. An agent that holds several credentials picks per site.
- No authorization code flow at the issuer, no deferred issuance, no encrypted responses to the verifier.
- `x509_san_dns:` and `x509_hash:` requests are checked against the certificate in the request, not against a
  trust store: the agent knows it is talking to the holder of that certificate, and the pin says which one it
  expects. A trust store for verifier certificates is a deployment choice this reference does not make.
