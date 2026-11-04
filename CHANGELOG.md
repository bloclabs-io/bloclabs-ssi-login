# Changelog

## 0.1.0-dev (unreleased)

- Correct finality, webhook delivery, contract build and claim-retention documentation; add regression coverage for atomic state transitions, login ordering, cookie attributes and version-aware WordPress test installs (#33).

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
