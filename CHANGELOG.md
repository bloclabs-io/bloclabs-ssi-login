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
- One reviewer per pull request (founder, 2026-11-03): Codex reviews every PR when it opens, with its security
  review; the Claude Code Review workflow runs only when a PR gets the `claude-review` label. `AGENTS.md` holds the
  rules and roles for every coding agent and Codex's review rules; its "Who does what" section is the single place
  for roles (Fable writes the code here). Repository process only, no code change.
- Fix from the Fable review (#27): on multisite, the settings page and its save require `manage_network_options`,
  so a site administrator cannot point the plugin at another bridge or FireFly, or turn on account creation.
