# Changelog

## 0.4.0-dev (unreleased)

- Agent login, bearer authentication and scope enforcement (#91, ADR 0007 follow-up 4/7). `Authorization: Bearer
  bssi_…` authenticates a REST request over HTTPS as the token's user. WordPress determines the user at bootstrap,
  before REST routing, so `determine_current_user` (priority 20, where Application Passwords sit) only reserves a
  request that carries one of our tokens as nobody's, and the token is checked at the REST boundary, in
  `rest_authentication_errors` (priority 90), before any route runs: an expired or revoked token, a missing user, a
  plain-HTTP request, or an account that `wp_authenticate_user` or `authenticate` vetoes (applied on every request,
  so a lockout, ban or multisite spam flag cuts an agent off at once) answer 401, never fall back to a cookie or to
  anonymous, and fire `bloclabs_ssi_agent_token_refused` with the reason and the token's hash for lockout plugins.
  Outside REST the token is never checked and the request stays anonymous, so wp-admin, wp-login.php, admin-ajax.php
  and XML-RPC never see a token's user. A bearer value that is not ours is left to whatever plugin issued it; the
  token is a header or nothing, never a query argument or a cookie; `last_used_at` is written at most once a minute.
  `map_meta_cap` answers `do_not_allow` for every primitive capability outside the token's scope, for the denylist
  and for the account's self-service meta capabilities (`edit_user`, `delete_user`, `promote_user` and the
  Application Password ones), which confines a multisite super administrator too; `user_has_cap` intersects the
  account's capabilities with the scope's, so a scope never grants what the account lacks and a demoted account's
  agents are demoted with it. Routes tell a token request from a session with `BearerAuthentication::current()`.
  Not registered until the tokens table (1/7) lands.
- Agent login, token issuance (#90, ADR 0007 follow-up 3/7). The checks every verified attempt passes (the verifier's
  result against the on-chain commitments, the user against the `wp_authenticate`, `wp_authenticate_user`,
  `authenticate` and `bloclabs_ssi_allow_login` filters) move from `LoginFinalizer` into `LoginChecks`, shared with
  the new `TokenIssuer`, which turns a verified agent attempt into an opaque `bssi_` bearer token: the account is the
  one the credential's `acts_for` names, if it has turned on *Agents may act for this account*, or the one the
  agent's own key is linked to, and nothing is ever provisioned; the scope is requested ∩ the credential's `scope`
  ∩ the site's `agent_scopes` (`read`, `content`, plus a site's own through `bloclabs_ssi_agent_scopes`, never an
  administrative capability); `bloclabs_ssi_agent_token` may narrow or refuse; the lifetime is `agent_token_ttl`
  bounded by the credential's expiry, which the bridge's result may now report as `expires_at`; the attempt is
  consumed and the token row written in the same request, so one attestation yields at most one token; no cookie
  is set and `wp_login` does not fire, `bloclabs_ssi_agent_token_issued` does. Settings `agent_login_enabled` (off),
  `agent_credential_query`, `agent_token_ttl` and `agent_scopes`. The routes (2/7) and the tokens table (1/7) are
  separate pull requests, so nothing is reachable yet.

## 0.3.0 (2026-11-06)

First release. The first end-to-end logins with a real phone wallet (Paradym on iOS) ran on 2026-11-06, same device
and cross device, including linking a credential to an existing account. Not externally reviewed yet (milestone 1.0).


- Offer the existing SSI login block on WooCommerce My Account and checkout login forms, returning to the Woo page after login (#98).

- Same-device login through the browser's Digital Credentials API (#76). With `BRIDGE_DC_API_ORIGINS` and
  `VERIFIER_PUBLIC_URL` set, the bridge opens a second walt.id session (`dc_api_openid4vp`, bound to the login
  pages' origins) next to the QR code's and returns it as `dc_api`: the `requests` for `navigator.credentials.get`
  and the verifier's `response_url`. Where the browser has the API, the login page asks the wallet through it on
  the click, posts the answer to the verifier without cookies, and falls back to the QR code and wallet link when
  the prompt is dismissed, unsupported or undeliverable; whichever session answers first is attested once under
  the attempt's correlation id. Without the setting or the API nothing changes. docs/BRIDGE-API.md defines the
  field.
- Auto-provisioned accounts take their display, first and last name from the disclosed `given_name` and `family_name` when the credential has no `name` claim, as SD-JWT VC identity credentials usually don't; the display name still falls back to the login, and the e-mail claim is still never used (#56).
- ADR 0006: issuer trust moves from the bridge's walt.id `allowed-issuer` policy to an owner-governed on-chain
  `TrustedIssuerRegistry` of `(issuer, vct)` pairs, which the bridge queries through FireFly before it attests, with
  what stays off chain (signatures, holder binding, revocation) and the migration; ARCHITECTURE.md and
  SECURITY-MODEL.md (threats 22 and 23) describe issuer trust accordingly (#74). Docs only, no code change.
- Bridge: with `FIREFLY_REGISTRY_API` set to the `TrustedIssuerRegistry` contract's FireFly API, every presented
  credential's issuer and `vct` are checked on chain (`isTrusted`) before the decision is attested. An untrusted pair
  is attested as a rejection (`result = 2`); when FireFly cannot answer, the attempt fails closed and nothing is
  attested. Unset, the walt.id `allowed-issuer` policy decides alone, as before (#73).
- ADR 0007, agent login with an application token (#75): how an agent proves who it is (its holder key) and who
  it acts for (an `acts_for` claim from a trusted issuer, or a key linked here) with an SD-JWT VC and no browser;
  the opaque, scoped, short-lived bearer token WordPress issues instead of a cookie, its storage, lifetime and
  revocation; the unchanged on-chain attestation; threats; and the follow-up implementation issues. Docs only,
  no code change.
- The "Log in with a digital credential" button and the wallet link on wp-login.php keep their own text, background and
  border colours, pinned as one set, so a theme or login customiser that recolours links or buttons cannot leave the
  text unreadable; a theme recolours them through the `--bloclabs-ssi-button-*` custom properties. The focus ring
  stays visible on any page background (#55).
- Support signed walt.id authorization requests with `x509_san_dns` or `x509_hash` client identities, private PEM-to-config setup and a self-signed certificate smoke test that uses the default Docker host/context, including Docker Desktop (#72).
- Link and unlink credentials from your own profile using account- and browser-bound, single-use verified attempts (#70).
- Add the owner-governed TrustedIssuerRegistry for exact issuer/vct pairs, two-step ownership, executable contract tests in CI and FireFly setup instructions (#71).

- Handoff labels use live PR draft/state data and an Actions-bot head checkpoint so replaced push jobs and delayed old handoffs cannot preserve an earlier approval (bloclabs-io/blocLabs-LearnPress-API-Extension#97).

- Correct finality, webhook delivery, contract build and claim-retention documentation; add regression coverage for atomic state transitions, login ordering, cookie attributes and version-aware WordPress test installs (#33).
- Installation and login robustness (#32): fail activation when tables cannot be created, throttle upgrade retries, clear stale wallet prompts on lost bindings, keep long wallet URLs usable when QR encoding fails, use same-origin REST URLs, and require two-step attestor ownership transfer.
- Add the Handoff stage-label workflow with the four coder/reviewer accounts, including Codex and Grok bots; preserve whole-line commands and Britney-only merge handoffs (#52).

- FireFly event safeguards (#31): require the emitting attestor address, serialize polling with shared cooldowns, order by protocol ID with a clock-skew margin, reject repeated contract decisions, upsert subscriptions on rotation and return JSON webhook acknowledgements.

- Behind Apache `mod_remoteip` (on in the official WordPress Docker image) or nginx `real_ip`, `client_ip_header` must
  stay empty: the server resolves the client and trims the header, so the plugin would read whatever the visitor wrote
  and the per-client cap could be rotated out of. Documented in readme.txt, the field's help and SECURITY-MODEL
  threat 11; the settings page now warns when the configured header is missing from the administrator's own
  request (#45).
- `wp bloclabs-ssi subscribe` takes the webhook address as `--webhook-url`. It used to declare `--url`, which WP-CLI
  keeps for itself as its global site-URL option, so the command never received it and subscribed FireFly to the
  site's public REST URL regardless (#39).
- AGENTS.md: Britney tests and deploys; Fable, Codex and Grok code and review (founder, 2026-11-04). Repository process only, no code change.
- README brought up to date (multisite requirements, the integration-test command, agent login marked as planned, the WordPress.org listing as a founder decision). Docs only, no code change.
- Reference verifier bridge in `bridge/` (TypeScript on Node 22, no runtime dependencies, ADR 0005): the two routes
  of docs/BRIDGE-API.md behind a bearer token; OpenID4VP 1.0 delegated to walt.id verifier-api2 (1.2.0) through its
  session API and webhooks; subject and presentation commitments; `attest()` through FireFly with an idempotency
  key; results readable only after the attestation and deleted after the attempt lifetime plus a minute.
  A query that could present several credentials is refused at start-up, `presentation_hash` is the SHA-256 of
  the RFC 8785 canonical JSON of the parsed `vp_token` (pinned by test vectors), and a wallet's decline is
  attested as a rejection. Dockerfile, docker-compose example with placeholders, CI job (#21).
- The subject commitment is blinded with a per-attempt secret that WordPress generates and shares with the bridge
  only (`blinding_secret` in the bridge request, schema version 2 adds the column); the correlation id alone is
  public on chain, so it could not keep logins unlinkable (#25).
- `AGENTS.md` no longer gives an end date for Grok in Cursor (founder, 2026-11-04). Repository process only, no code change.
- Plugin framework: login block on `wp-login.php`, REST routes (`initiate`, `status`, `complete`, `firefly/events`),
  cookie-bound attempts in a custom table, user linking and optional provisioning, settings screen, WP-CLI command.
- FireFly integration: webhook doorbell with pull confirmation, polling fallback, `LoginAttested` decoder.
- `SsiLoginAttestor` contract; checked on FireFly v1.5.0 with Besu QBFT.
- Architecture, FireFly flow, bridge API, security model and four ADRs.
- Fixes from the Grok review (#4): `/complete` consumes the attempt only after every check; the `authenticate`
  filter runs and the veto fails closed; the page token works for logged-in visitors; polling pages through all
  attestations; events are always re-read; reorged logs are ignored; rate limiting counts every attempt; the
  binding cookie follows the home URL's scheme; network activation is refused; and smaller fixes.
- One reviewer per pull request (founder, 2026-11-03): Codex reviews every PR when it opens, with its security
  review; the Claude Code Review workflow runs only when a PR gets the `claude-review` label. `AGENTS.md` holds the
  rules and roles for every coding agent and Codex's review rules; its "Who does what" section is the single place
  for roles (Fable writes the code here). Repository process only, no code change.
- Fix from the Fable review (#27): on multisite, the settings page and its save require `manage_network_options`,
  so a site administrator cannot point the plugin at another bridge or FireFly, or turn on account creation.
- Fix from the Fable review (#28): a credential login now runs the `wp_authenticate` action and the
  `wp_authenticate_user` filter before `authenticate`, so lockout, ban and disabled-account plugins refuse it as they
  would a password login.
- Fix from the Fable review (#26): behind a proxy the rate-limit key is taken `client_ip_proxies` entries from the
  right of the forwarded-for header, never from the left, where the sender writes; a header that cannot name the
  client refuses the request. A client is an IPv4 address or an IPv6 /64, a site-wide cap (`max_pending_total`,
  default 500 per 10 minutes) backs the per-client one, both caps are on the settings page, and they are checked
  again by the row's rank after the insert, so a parallel burst cannot overshoot. Schema version 3 adds an index
  on `created_at` for the site-wide count.
- Fixes from the Fable review (#29): the auth cookie is set by `is_ssl()`, as a password login does, so behind a TLS
  proxy that hides HTTPS from PHP a credential login no longer ends on `reauth=1`; a `bloclabs_ssi_resolve_user`
  refusal removes the account provisioned for it; a refused provisioned account is deleted network-wide on
  multisite unless another site holds it by then, a subject whose deterministic login is held by a stranded network
  account (or by its account on another site under a shared subject key) is given that account, and a network's
  refusal to add that account to the site (`can_add_user_to_blog`) refuses the login; a concurrent provision of the
  same subject answers "retry" instead of "not linked"; `identities.issuer` is a TEXT column (schema version 4), so
  long `did:jwk` and `did:ion` issuers no longer refuse every login; and the settings form no longer unslashes
  twice, so backslashes typed into secrets survive.
- Fixes from the Fable review (#30): the bridge's 408, 425 and 429 are retried like 409 and 5xx instead of failing
  a verified attempt; a result whose `presentation_hash` is not 64 hex characters (a `0x` prefix is stripped) or
  that names no subject fails the attempt at once instead of reading as a commitment mismatch, and
  `docs/BRIDGE-API.md` says which answers WordPress retries (409, never 404, until the result is readable) and that
  the hash carries no `0x` prefix; a login attempt that cannot be stored answers 503 without a binding cookie
  instead of a 500; and a bridge request id that cannot be stored (over 191 characters) is refused at `/initiate`
  instead of failing every completion of that attempt.
