# Changelog

## 0.1.0-dev (unreleased)

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
