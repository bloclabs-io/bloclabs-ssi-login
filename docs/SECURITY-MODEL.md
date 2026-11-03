# Security model

What an attacker might try, and what stops them. "Bridge" is the verifier sidecar ([BRIDGE-API.md](BRIDGE-API.md)).

| # | Threat | Mitigation | Where |
|---|---|---|---|
| 1 | **Cross-device QR relay.** The attacker opens the login page, sends the QR code to a victim (phishing page, chat), and the victim's wallet logs the attacker's browser in. | No cross-device flow fully prevents this. OpenID4VP 1.0 §14.2 admits its Response Code defence does not work across devices, and RFC 10027 (BCP 247) lists the mitigations used here: short-lived single-use requests (TTL 60–600 s, default 180), rate limits, and a request signed by the verifier's certified identity (`x509_san_dns:` client id), so the wallet can show who is asking. **Prefer same-device login through the Digital Credentials API** (roadmap), which binds the request to the page's origin. | Bridge, `InitiateController`, roadmap |
| 2 | Guessing or stealing an attempt id to poll or complete someone else's login. | 128-bit `public_id` plus a 256-bit secret in a `__Host-`, HttpOnly, SameSite=Strict cookie whose hash the attempt stores. Unknown and foreign attempts both answer 404. | `BrowserBinding`, `BrowserController::bound_attempt()` |
| 3 | Cross-site requests to the login endpoints. | SameSite=Strict cookie plus the login page nonce. For logged-out visitors WordPress nonces are shared by all anonymous users, so the nonce is a cross-site check only, not a binding. | `BrowserController::check_page_request()` |
| 4 | Forged webhook delivery. | Shared secret header (≥ 32 characters, constant-time compare) and optional IP allowlist on the direct peer address. The body is never trusted: the event is re-read from FireFly by id, and a 404 is ignored. FireFly cannot sign webhooks (v1.5), which is why the re-read matters. | `WebhookController`, `AttestationProcessor` |
| 5 | Replayed webhook or poll applying an attestation twice; double click on complete. | Compare-and-set status transitions (`UPDATE … WHERE status = ?`); `consumed` is terminal. | `AttemptRepository::transition()` |
| 6 | A forged `LoginAttested` event from another contract. | The decoder accepts only the configured listener, which FireFly binds to the attestor's address; the contract lets only owner-authorised verifiers emit. | `ContractEventDecoder`, `SsiLoginAttestor` |
| 7 | A compromised or buggy bridge answering WordPress with a different subject than it attested. | WordPress recomputes `sha256(correlation_id ":" subject_id)` and compares the presentation hash with the on-chain values. A mismatch refuses the login and fires `bloclabs_ssi_commitment_mismatch`. | `LoginFinalizer` |
| 8 | Tracking people by reading the chain. | Only commitments go on chain, salted with the random per-attempt `correlation_id`; the same holder's logins are unlinkable. The browser never sees `correlation_id`. | Contract, `Attempt` |
| 9 | Account takeover through claim matching ("this credential says ada@example.com"). | Not offered. Subjects log in only to accounts they were linked to, or (opt-in) get a new account. | `UserResolver` |
| 10 | Self-registration into a powerful role. | Provisioning never grants a role that can `manage_options`, `edit_users` or `promote_users`; it falls back to subscriber. | `UserResolver::safe_role()` |
| 11 | Table flooding by anonymous `/initiate` calls. | Per-IP cap on pending attempts (default 10 per 10 minutes, keyed HMAC of the IP), hourly purge, rows deleted after a day. Behind a proxy, set `client_ip_header` only if the origin is reachable through that proxy alone. | `InitiateController`, `PurgeExpired`, `ClientIp` |
| 12 | Open redirect after login. | `redirect_to` is validated with `wp_validate_redirect()` at initiate and again after the `login_redirect` filter. | `InitiateController`, `CompleteController` |
| 13 | Malicious wallet URL from a compromised bridge (`javascript:`). | Only `openid4vp://` and `https://` are accepted, server side and again in the browser; values are set with `textContent` and `href`, never HTML. | `PresentationOffer`, `login.js` |
| 14 | Secrets leaking through the database or settings screen. | Secrets can be pinned in `wp-config.php` (`BLOCLABS_SSI_*`), are never printed back, and are excluded from REST. | `Settings`, `SettingsPage` |
| 15 | Exposing FireFly. | FireFly core has no authentication. Keep it on a private network; the plugin supports an `Authorization` header for an authenticating proxy. | Deployment |
| 16 | Bypassing other login protections (2FA, lockouts) that hook `wp_authenticate`. | Credential login does not go through `wp_signon()`. Sites that require a second factor should veto with `bloclabs_ssi_allow_login`. `wp_login` still fires for auditing plugins. | `LoginFinalizer` |

## Residual risks

- Threat 1 is reduced, not removed, until the Digital Credentials API path ships. Treat cross-device credential login
  like any QR login: keep the TTL short and the wallet's display of the verifier identity meaningful.
- The bridge holds the verifier's request-signing keys and the chain signing key. It is the most sensitive component;
  run it with the least network exposure that wallets allow.
- Trust in issuers, and revocation checks, live in the bridge in 0.1. The on-chain trusted-issuer registry on the
  roadmap makes that policy auditable too.
