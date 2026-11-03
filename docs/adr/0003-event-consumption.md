# ADR 0003: Webhook doorbell with pull confirmation, polling as fallback

**Status:** accepted, 2026-11-03

## Question

Should WordPress consume FireFly events through a persistent WebSocket listener (a background PHP / WP-CLI
process), or through a public REST webhook that FireFly POSTs to?

## Comparison

| | WebSocket daemon (`wp … listen`) | Webhook to a REST route |
|---|---|---|
| Fits PHP's request model | No: a long-running PHP process, needing a supervisor, reconnects, memory hygiene and a WebSocket client library | Yes: one short request per event |
| Works on shared hosting | No | Yes |
| Needs FireFly → WordPress reachability | No (outbound only) | Yes |
| Delivery guarantees | Acks; replays from the subscription offset after reconnect | FireFly retries on non-2xx (`retry`, `fastack: false`) |
| Authentication | WordPress dials out, nothing to protect | Static secret header only: FireFly v1.5 cannot sign webhooks |
| Latency | Lowest | Same, plus one HTTP hop |

## Decision

1. **Webhook as a doorbell.** FireFly's webhook subscription POSTs to `/wp-json/bloclabs-ssi/v1/firefly/events`
   with a secret header. WordPress does not trust the body: it re-reads the event with
   `GET /events/{id}?fetchreference=true` and only then changes state. A leaked secret lets an attacker ring the bell,
   not forge a login.
2. **Polling as the safety net.** When a pending attempt is older than `poll_fallback_after` (15 s), or when the site
   runs in *Polling only* mode, the status endpoint queries FireFly's blockchain events for the listener, at most
   once every 3 seconds per attempt. Missed webhooks therefore delay a login; they never lose it.
3. **No daemon in 0.1.** Both paths go through the same `AttestationProcessor`, so a WP-CLI WebSocket consumer can be
   added later for deployments that need it.

## Consequences

- Recommended topology: FireFly delivers over a private network to WordPress's internal address, with the IP
  allowlist set to that network.
- WordPress needs read access to FireFly in every topology (private network or authenticating proxy).
