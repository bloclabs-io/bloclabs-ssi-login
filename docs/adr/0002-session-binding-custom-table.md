# ADR 0002: Login attempts in a custom table, bound by a cookie

**Status:** accepted, 2026-11-03

## Question

Where does the transient state that ties a browser session to a FireFly event live, without bloating `wp_options`?

## Options

| Option | Problem |
|---|---|
| Transients | Without a persistent object cache they are rows in `wp_options`. Anonymous visitors create them, webhooks update them, and expired ones are only removed lazily. No atomic compare-and-set, so a replayed webhook and a click can race. Lookup by correlation id would need a second transient per attempt. |
| Object cache only | Not durable, and absent on many hosts. A cache eviction would silently lose a login in progress. |
| User meta / post meta | No user exists yet; meta values are not indexed. |
| **Custom table** | Chosen. |

## Decision

`{prefix}bloclabs_ssi_attempts`, one row per attempt, with unique keys on `public_id` and `correlation_id`, an index
on `(status, expires_at)`, and status changes as `UPDATE … WHERE id = ? AND status = ?`. An hourly cron expires
stale rows and deletes rows older than a day.

The browser holds a 256-bit secret in a `__Host-` HttpOnly, SameSite=Strict cookie; the row stores its SHA-256.
WordPress nonces are kept as a cross-site check only, because for logged-out visitors they are identical for
everyone (user 0, no session token).

## Consequences

- `wp_options` gains two small rows (settings, subject key) and one autoloaded schema version.
- Exactly-once semantics for attestations and completion.
- Multisite: one table per site, created on activation (network activation needs a per-site loop, on the roadmap).
