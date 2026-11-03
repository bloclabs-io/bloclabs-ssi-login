# Changelog

## 0.1.0-dev (unreleased)

- Reference verifier bridge in `bridge/` (TypeScript on Node 22, no runtime dependencies, ADR 0005): the two routes
  of docs/BRIDGE-API.md behind a bearer token; OpenID4VP 1.0 delegated to walt.id verifier-api2 (1.2.0) through its
  session API and webhooks; subject and presentation commitments; `attest()` through FireFly with an idempotency
  key; results readable only after the attestation and deleted after the attempt lifetime plus a minute.
  Dockerfile, docker-compose example with placeholders, CI job (#21).
- The subject commitment is blinded with a per-attempt secret that WordPress generates and shares with the bridge
  only (`blinding_secret` in the bridge request, schema version 2 adds the column); the correlation id alone is
  public on chain, so it could not keep logins unlinkable (#25).

- Plugin framework: login block on `wp-login.php`, REST routes (`initiate`, `status`, `complete`, `firefly/events`),
  cookie-bound attempts in a custom table, user linking and optional provisioning, settings screen, WP-CLI command.
- FireFly integration: webhook doorbell with pull confirmation, polling fallback, `LoginAttested` decoder.
- `SsiLoginAttestor` contract; checked on FireFly v1.5.0 with Besu QBFT.
- Architecture, FireFly flow, bridge API, security model and four ADRs.
- Fixes from the Grok review (#4): `/complete` consumes the attempt only after every check; the `authenticate`
  filter runs and the veto fails closed; the page token works for logged-in visitors; polling pages through all
  attestations; events are always re-read; reorged logs are ignored; rate limiting counts every attempt; the
  binding cookie follows the home URL's scheme; network activation is refused; and smaller fixes.
