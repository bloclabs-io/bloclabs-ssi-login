# Changelog

## 0.1.0-dev (unreleased)

- Plugin framework: login block on `wp-login.php`, REST routes (`initiate`, `status`, `complete`, `firefly/events`),
  cookie-bound attempts in a custom table, user linking and optional provisioning, settings screen, WP-CLI command.
- FireFly integration: webhook doorbell with pull confirmation, polling fallback, `LoginAttested` decoder.
- `SsiLoginAttestor` contract; checked on FireFly v1.5.0 with Besu QBFT.
- Architecture, FireFly flow, bridge API, security model and four ADRs.
- Fixes from the Grok review (#4): `/complete` consumes the attempt only after every check; the `authenticate`
  filter runs and the veto fails closed; the page token works for logged-in visitors; polling pages through all
  attestations; events are always re-read; reorged logs are ignored; rate limiting counts every attempt; the
  binding cookie follows the home URL's scheme; network activation is refused; and smaller fixes.
