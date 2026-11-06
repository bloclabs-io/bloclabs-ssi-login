# ADR 0007: Agent login with an application token

**Status:** accepted, 2026-11-06 (#75). Not implemented yet: the follow-up issues are listed at the end.

## Question

A software agent (a script, a bot, an assistant working for someone) holds a Verifiable Credential and a key and
wants to use this site's REST API. It has no browser, so it can neither scan a QR code nor hold the cookie that
[ADR 0002](0002-session-binding-custom-table.md) binds a login attempt to. How does it prove who it is and who it
acts for? What does WordPress hand it instead of a cookie, with which format, scope, lifetime and revocation? How is
the decision attested on chain like a person's login, and what can go wrong?

[ARCHITECTURE.md](../ARCHITECTURE.md) ("Verifiable agents") and the README roadmap (0.4) promise this; #64 is the
parent issue.

## Facts (checked 2026-11-06)

- **OpenID4VP needs neither a browser nor a phone.** A wallet is whatever holds the holder key: it fetches the
  request object from `request_uri`, builds the presentation (for SD-JWT VC, the credential plus a key-binding JWT
  over the verifier's `nonce` and `aud`) and posts it to the verifier's `direct_post` endpoint. An agent with an
  SD-JWT VC holder library and its key answers the bridge's request exactly as a phone wallet does, and the verifier
  does not need to tell the two apart.
- **The bridge already derives the subject from the holder key** (`cnf`, as an RFC 9278 thumbprint URI or a DID),
  never from a claim, and serves the disclosed claims only after the attestation ([BRIDGE-API.md](../BRIDGE-API.md)).
  An agent credential is an SD-JWT VC like any other: the bridge, the contract and the FireFly path verify it as
  they are.
- **WordPress has one built-in non-cookie credential: Application Passwords** (core since 5.6). They authenticate
  REST and XML-RPC requests with HTTP Basic over HTTPS, are 24 characters stored hashed in user meta, carry the
  user's full capabilities, never expire, and are revoked from the profile screen, WP-CLI or
  `/wp/v2/users/{id}/application-passwords`. They plug into `determine_current_user` and `authenticate` at
  priority 20. Sites turn them off with `wp_is_application_passwords_available`, which hardening plugins commonly do.
- **WordPress has no scoped or delegated authorisation of its own.** It has the `user_has_cap` and `map_meta_cap`
  filters, which can narrow what one request may do, and `wp_is_rest_endpoint()` (6.5+; this plugin requires 6.6)
  to tell a REST request from wp-admin. A user may always edit their own profile: `edit_user` on oneself maps to no
  primitive capability, which covers the password, the e-mail address and Application Passwords.
- **Agent identity standards are still forming.** ERC-8004 (Draft), the DIF Trusted AI Agents WG, the W3C Agent
  Identity Registry CG and the OpenID AIIM CG have no protocol to adopt yet (ARCHITECTURE.md). This ADR uses plain
  SD-JWT VC claims and the trusted-issuer registry of [ADR 0006](0006-trusted-issuer-registry.md) (#74), so a later
  profile can replace the claim names without changing the token.

## Options

### Who the agent acts for

| Option | Problem |
|---|---|
| 1. The agent logs in with the principal's own credential and key. | Then it *is* the principal: nothing tells an agent's actions from the person's, the agent cannot be scoped or revoked without revoking the person, and the person's holder key leaves their wallet. |
| 2. The principal (or an administrator) links the agent's key to an account in WordPress; the credential proves only the agent's identity. | No issuer has to know about the delegation, but every one is a manual WordPress step and the credential says nothing about the relationship. **Kept as the path when the credential names no principal.** |
| 3. **An agent credential whose trusted issuer names the principal (`acts_for`).** | The issuer is the trust root of the delegation, so who may issue agent credentials matters (ADR 0006), and the principal must be able to see and cut off agents acting for them. **Chosen.** |

### What WordPress issues

| | **Opaque bearer token in a plugin table** | Core Application Password | JWT signed by WordPress | Sender-constrained token (a proof signed by the agent's key on every request) |
|---|---|---|---|---|
| Scope | A column, enforced per request | None: the user's full capabilities | A claim, enforced per request | A claim |
| Lifetime | A column: minutes to a day | None | `exp` | `exp` |
| Revocation | Immediate, a row flag | Immediate, from the core profile screen | Needs a denylist anyway, or very short lifetimes | As for the format it extends |
| Keys in WordPress | None | None | A signing key in the database, against ADR 0001 | None to sign with, but WordPress verifies an ES256 signature on every request: a cryptographic surface in PHP |
| Transport | `Authorization: Bearer` | HTTP Basic with the user's login name | Bearer | Bearer plus a proof header |
| Works when a site has turned Application Passwords off | Yes | No | Yes | Yes |
| Binding to the on-chain decision | Columns | The `app_id` field, misused | A claim | A claim |
| Cost per request | One indexed lookup | A password-hash check | A signature check | A lookup and a signature check |

**Chosen: the opaque bearer token.** Application Passwords were the closest and their profile screen is worth
copying, but they have no scope and no lifetime, cost a password-hash check per request, and are turned off on many
hardened sites. A JWT puts a signing key into WordPress and still needs the lookup for revocation. A
sender-constrained token is the right next step once the token is in use: the token row can store the agent's key
thumbprint, and the proof can be required by a later ADR without changing the format.

## Decision

### 1. The agent credential

An SD-JWT VC (`dc+sd-jwt`), bound to the agent's key (`cnf`), of a credential type the site chooses (`vct`, for
example `https://issuer.example.com/credentials/agent`), issued by an issuer the registry trusts for that type.
The bridge gets a second named query, `agent` by default, that pins `vct_values` and asks for the claims below;
the registry pair (issuer, `vct`) of [ADR 0006](0006-trusted-issuer-registry.md) decides who may issue agent
credentials, with walt.id's `allowed-issuer` policy until the registry is wired in (#73).

| Claim | Required | Meaning |
|---|---|---|
| `cnf` | yes | The agent's key. Its RFC 9278 thumbprint URI, or the DID behind `cnf.kid`, is the agent's `subject_id`: **who it is**, derived exactly as for a person. |
| `acts_for` | no | **Who it acts for**: the principal's subject id, the string the bridge derives from the principal's own credential (thumbprint URI or DID). The issuer learns it when the principal authorises the agent; how the issuer does that is the issuer's business. |
| `agent` | no | `name` and `operator`, for display: the principal's token list, the label kept with the token. Never used for a decision. |
| `scope` | no | The most the issuer lets this agent do, as scope names (below). Absent: the credential adds no limit. |
| `exp` | yes (SD-JWT VC) | Bounds the token: it never outlives the credential. |

An agent credential whose `acts_for` names nobody is an identity credential: the agent gets a token only if its own
key was linked to an account here (option 2 above), either an account of its own that an administrator created and
linked, or the principal's, if the principal linked the agent's key there. Nothing is ever provisioned for an agent,
whatever `linking_policy` says: bots do not self-register.

### 2. The flow without a browser

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent (key + credential)
    participant WP as WordPress
    participant BR as Verifier bridge
    participant FF as FireFly + chain

    A->>WP: POST /agent/initiate {scope}
    WP->>BR: POST /v1/presentation-requests {correlation_id, nonce, blinding_secret, query: "agent", expires_at}
    BR-->>WP: {id, wallet_url}
    WP-->>A: 201 {attempt, attempt_secret, wallet_url}
    A->>BR: GET request_uri (OpenID4VP request object)
    A->>A: check the verifier's identity, build the presentation + key-binding JWT
    A->>BR: POST direct_post {vp_token}
    BR->>FF: attest(correlationId, result, subjectCommitment, presentationHash)
    FF-->>WP: LoginAttested (webhook doorbell, re-read; or polling)
    loop until verified
        A->>WP: POST /agent/token {attempt} + X-Bloclabs-Ssi-Attempt
        WP-->>A: 409 pending
    end
    WP->>BR: GET /v1/presentation-requests/{id}/result
    WP->>WP: commitments, acts_for → user, login filters, scope, consume attempt
    WP-->>A: 200 {token, expires_at, scope}
    A->>WP: GET /wp-json/wp/v2/posts (Authorization: Bearer bssi_…)
```

Three REST routes next to the browser's, all under `/wp-json/bloclabs-ssi/v1/`, all answering 404 while
`agent_login_enabled` is off:

| Route | Carries | Answers |
|---|---|---|
| `POST /agent/initiate` | `{"scope": ["content"]}` (default `["read"]`) | `201 {attempt, attempt_secret, wallet_url, expires_in, poll_after}` |
| `POST /agent/token` | `{"attempt": "<public id>"}` and the header `X-Bloclabs-Ssi-Attempt: <attempt_secret>` | `409 pending` with `poll_after` until the chain has said verified; then, once, `200 {token, token_type, expires_at, scope, user_id, delegated}`; afterwards 409 `already used` |
| `DELETE /agent/token` | `Authorization: Bearer <token>` | revokes that token |

What differs from the browser routes:

- **No page token.** There is no page. The routes are public like `/initiate` and count against the same per-client
  and site-wide caps, in the same window and the same table (SECURITY-MODEL threat 11).
- **The binding travels in the body and a header, not a cookie.** Same 256-bit secret, same SHA-256 in
  `binding_hash`, same `bound_attempt()` check: a `HeaderBinding` next to `BrowserBinding`, behind one interface.
  Unknown and foreign attempts answer 404, as today.
- **Attempts carry a `kind`** (`browser` or `agent`) and the `requested_scope` (schema version 5). The browser routes
  refuse agent attempts and the agent routes refuse browser attempts, both with 404. Without that, an agent attempt
  could be completed through `/complete` (the secret set as the cookie, plus the page token, which anyone can read
  from the login page) into a full cookie session with no scope at all.
- **The token route reconciles** a pending attempt as `/status` does, so polling-only deployments (ARCHITECTURE.md
  topology B) work for agents too.

Unchanged: `AttemptRepository::open()`, the rate limits, the bridge call (with the `agent` query instead of
`credential_query`), the webhook and polling paths, `AttestationProcessor`, the contract.

The agent's side: open the attempt; fetch the request object from the `request_uri` in `wallet_url`; check that the
verifier's identity in the signed request (`x509_san_dns:` client id) is the site it meant to log in to; build the
presentation with its key; post it; poll the token route; use the token; delete it when the job is done. A reference
agent client for the demo stack is a follow-up (#64 asks for the flow end to end).

### 3. Issuing the token

A `TokenIssuer` next to `LoginFinalizer`, sharing its checks (the common part is extracted, not copied), in this
order:

1. The attempt is `verified`, not expired, and `kind = agent`.
2. Fetch the result from the bridge. A transient error answers 503 and leaves the attempt verified, so the agent
   retries; a definitive one fails it (SECURITY-MODEL threat 17).
3. Check `subject_commitment` and `presentation_hash` against the on-chain values, exactly as `/complete` does
   (threat 7). A mismatch fails the attempt and fires `bloclabs_ssi_commitment_mismatch`.
4. Resolve the user. With `acts_for`: the identities row for `HMAC(subject_key, acts_for)`, and that user has turned
   on *Agents may act for this account*. Without: the identities row for the agent's own subject id. Nothing is
   provisioned. No user, or the account opted out: the attempt fails, 403.
5. The checks a password login gets, on the resolved user: the `wp_authenticate` action, the `wp_authenticate_user`
   and `authenticate` filters, then `bloclabs_ssi_allow_login`, which must return exactly `true` (threat 16), so a
   site's veto covers agents. Then `bloclabs_ssi_agent_token`, which may narrow the scope or the lifetime, or refuse.
6. Scope = requested ∩ the credential's `scope` ∩ the site's `agent_scopes`. Empty: refuse.
7. Consume the attempt (compare-and-set, exactly one request wins) and insert the token row in that same request.
   One attestation yields at most one token, ever.
8. Return the token once, in the JSON body. No `wp_set_auth_cookie()`, no `wp_login`: there is no interactive
   session, and plugins hooking `wp_login` may redirect or print. `bloclabs_ssi_agent_token_issued` fires instead.

### 4. The token

**Format.** `bssi_` followed by 43 base64url characters: 32 bytes from `random_bytes()`. The prefix is for secret
scanners and log filters; the rest is the secret. It is opaque: nothing can be read from it, so WordPress never
parses a token, and nothing in it names the user, the agent or the attestation. It is returned once and stored as
its SHA-256 (hex). A 256-bit random secret cannot be brute-forced through its SHA-256, and the lookup is one
indexed query; a slow password hash would cost that much on every API request for no gain.

**Storage.** `{prefix}bloclabs_ssi_tokens`, one table per site like the other two:

| Column | Purpose |
|---|---|
| `token_hash` | SHA-256 of the token, unique key |
| `user_id` | The account the token acts as |
| `delegated` | 1 when `acts_for` named the account, 0 when the agent's own key is linked to it |
| `agent_subject_hash`, `agent_label` | HMAC of the agent's subject id under the subject key (as in the identities table), and a label for people: the sanitised `agent.name` and `operator`, or the keyed fingerprint `IdentityRepository::label()` gives |
| `issuer` | The agent credential's issuer |
| `scope` | JSON list of scope names |
| `correlation_id`, `tx_ref`, `firefly_event_id` | Copied from the attempt: the on-chain decision this token came from, kept here because attempt rows are purged after a day |
| `created_at`, `expires_at`, `last_used_at`, `revoked_at` | Lifecycle. No addresses are stored |

Expired and revoked rows stay 30 days (`bloclabs_ssi_token_retention` filter) for the audit trail, then the hourly
purge deletes them.

**Use.** `Authorization: Bearer bssi_…` on `/wp-json/` requests over HTTPS. A `determine_current_user` filter at
priority 20, where Application Passwords sit, finds the row by hash and refuses an expired or revoked token, a
missing user, or a request that is not a REST request over HTTPS. A bearer value that does not start with `bssi_`
is not ours and is left to whatever plugin issued it. A refused token answers 401 through
`rest_authentication_errors`, never falls back to anonymous and never to a cookie, and fires
`bloclabs_ssi_agent_token_refused` for lockout plugins. `last_used_at` is written at most once a minute. The token
is not accepted on wp-admin, `wp-login.php`, `admin-ajax.php` or XML-RPC, not in a query string, and never as a
cookie; it is a header or nothing, so no cross-site page can attach it and no nonce is needed.

**Scope.** Scope names map to capability sets. 0.4 defines two: `read` (`read`) and `content` (`read`,
`edit_posts`, `edit_published_posts`, `publish_posts`, `delete_posts`, `upload_files`); `bloclabs_ssi_agent_scopes`
adds a site's own. A request authenticated by a token is confined by two filters:

- `user_has_cap` intersects the user's capabilities with the scope's. The intersection can only narrow: a scope
  never grants what the account lacks, and a demoted account's agents are demoted with it, on their next request.
- `map_meta_cap` adds `do_not_allow` to the account's self-service capabilities: `edit_user`, `delete_user`,
  `promote_user` and the Application Password capabilities (`create_app_password`, `list_app_passwords`,
  `read_app_password`, `edit_app_password`, `delete_app_password`, `delete_app_passwords`). Without this an agent
  with any scope could change the principal's password or e-mail, or mint an unscoped, non-expiring Application
  Password, because WordPress lets a user edit their own profile with no primitive capability to intersect.

No scope may ever contain what `UserResolver::safe_role()` refuses (`manage_options`, `edit_users`,
`promote_users`), nor `create_users`, `delete_users`, `unfiltered_html`, `unfiltered_upload`, `install_plugins`,
`activate_plugins`, `edit_plugins`, `edit_themes`, `install_themes`, `update_core` or any `manage_network_*`
capability; the filter's result is checked against that list.

**Lifetime.** `expires_at = min(issued + agent_token_ttl, credential exp)`; `agent_token_ttl` defaults to 3600 s and
is clamped to 300–86400. There is no refresh token: a new token means a new presentation and a new attestation, so
every token traces to one on-chain decision. The bridge must report the credential's `exp` for the bound to work:
the result route gains an optional `expires_at` (BRIDGE-API.md, a follow-up); without it the TTL alone applies.

**Revocation** is a row flag, effective on the next request:

- by the principal, from the token list on their profile screen (label, issuer, scope, issued, expires, last used,
  *Revoke*); turning *Agents may act for this account* off revokes every delegated token;
- by an administrator, from the user's profile, and with `wp bloclabs-ssi agent-tokens list|revoke`;
- by the agent itself, with `DELETE /agent/token`;
- automatically, on `deleted_user`, on `remove_user_from_blog`, when the identity link the token resolved through is
  removed, and on a password reset (`after_password_reset`), as WordPress destroys sessions then;
- not by the issuer: a credential revoked after the token was issued is not seen until the token expires. WordPress
  checks status at presentation only. The lifetime bounds the exposure; a site that needs faster reaction shortens it.

### 5. Attestation on chain

Nothing changes on chain: `attest(correlationId, result, subjectCommitment, presentationHash)`, with the **agent's**
holder key as the committed subject, so the chain records which agent presented, when, and to which verifier. The
principal is not on chain: the delegation is a claim, and the chain binds the subject and the presentation hash
only (ARCHITECTURE.md, trust boundary 5). WordPress checks the commitments before issuing a token exactly as before
setting a cookie, and the token row keeps the correlation id and the transaction reference, so every token can be
traced to its event and every event to the token it produced.

`acts_for` and the agent's claims are authenticated bridge HTTP data, like `issuer` and `claims` today. That is not
new trust: a compromised bridge can already name any subject it attested (threat 7 binds its HTTP answer to its own
attestation, no more). A site that wants agent decisions told apart on chain runs the agent flow through a second
bridge instance with its own authorised signing address: the `verifier` field of `LoginAttested` then says which
flow decided, with no contract change.

### 6. Settings, user setting and hooks

| Setting | Default | Meaning |
|---|---|---|
| `agent_login_enabled` | off | Registers the agent routes and the bearer filter |
| `agent_credential_query` | `agent` | The bridge query for agent attempts |
| `agent_token_ttl` | 3600 | Seconds a token lives, clamped to 300–86400 |
| `agent_scopes` | `read,content` | Scope names the site allows at all |

Per user: *Agents may act for this account* (user meta, off), on the profile screen with the token list. Hooks:
`bloclabs_ssi_agent_scopes` and `bloclabs_ssi_agent_token` (filters), `bloclabs_ssi_agent_token_issued`,
`bloclabs_ssi_agent_token_revoked` and `bloclabs_ssi_agent_token_refused` (actions). On multisite, tokens, like
identities, belong to the site that issued them.

## Threats

Numbered apart from [SECURITY-MODEL.md](../SECURITY-MODEL.md); the implementation moves them there.

| # | Threat | Mitigation | Where |
|---|---|---|---|
| A1 | A stolen token (an agent's logs, environment or memory). | Opaque, HTTPS-only, header-only; a scope that cannot reach the account's own settings; a lifetime of minutes to a day; revocation by the principal, an administrator or the agent; hashed at rest, so a database dump holds no usable token; `last_used_at` on the principal's list. | `TokenIssuer`, bearer filter, profile screen |
| A2 | Prompt injection: an attacker opens an agent attempt and feeds its `wallet_url` to the victim's agent, which presents the credential; the attacker, holding the attempt secret, gets the token. The agent-side form of the cross-device relay (threat 1). | The protocol cannot prevent it, as it cannot for people. The agent presents only to the request its own `/agent/initiate` returned and checks the verifier's identity in the signed request; the token is scoped and short-lived; the principal's list shows every token; the chain shows every presentation the agent made. | Agent client, bridge (signed requests), profile screen |
| A3 | A trusted issuer, or a compromised one, delegates any linked account to any agent. | The registry pins (issuer, `vct`); a site should run its own agent-credential issuer; delegation needs the principal's opt-in; every delegated token is listed and revocable; the login filters still run. | ADR 0006, `TokenIssuer`, profile screen |
| A4 | Scope escalation: using the token to change the principal's password or e-mail, mint an Application Password, or reach capabilities the scope does not list. | `map_meta_cap` denies the self-service capabilities; `user_has_cap` intersects with the scope; the denylist bars administrative capabilities from any scope. | Bearer filter |
| A5 | Completing an agent attempt through the browser route, or a browser attempt through the agent route. | `kind` on the attempt; each route refuses the other's attempts with 404. | `BrowserController`, agent controllers |
| A6 | Issuing two tokens for one attestation, or a token for a consumed attempt. | Compare-and-set consumption and the insert in the same request; `consumed` is terminal (threat 5). | `AttemptRepository::transition()` |
| A7 | Guessing an attempt to poll or complete another agent's login. | 128-bit `public_id` plus the 256-bit attempt secret in a header; unknown and foreign attempts both answer 404 (threat 2). | `HeaderBinding` |
| A8 | Guessing a token. | 256 bits of entropy, one indexed lookup; failures fire `bloclabs_ssi_agent_token_refused` for lockout plugins. | Bearer filter |
| A9 | Bots registering accounts. | The agent route never provisions, whatever `linking_policy` says. | `TokenIssuer` |
| A10 | The principal's account changes after issuance (role lowered, user deleted, credential unlinked). | Capabilities are read from the account on every request; deletion, removal from the site, unlinking and a password reset revoke. | Bearer filter, revocation hooks |
| A11 | A credential revoked at the issuer after the token was issued. | Not detected until expiry; the lifetime is the bound. Residual. | `agent_token_ttl` |
| A12 | Personal data on chain, in the database or in logs. | On chain: commitments only, as before. In the database: the agent's subject and the principal's `acts_for` as HMACs, a label, no addresses. In logs: nothing about the credential. | Contract, tokens table |
| A13 | A REST route that checks only `is_user_logged_in()` is reachable with any scope. | Core routes check capabilities. A site with such routes keeps agent login off, or guards them itself: the bearer filter exposes the current token, so a route can tell a token request from a session. Residual. | Deployment |
| A14 | Flooding `/agent/initiate` from headless clients. | The same per-client and site-wide caps as `/initiate`, counted in the same window. | `InitiateController` caps |

## Consequences

- Browser login is untouched, and the agent routes are off by default.
- Schema version 5: two columns on the attempts table and a tokens table.
- WordPress authenticates REST requests itself for the first time: one `determine_current_user` filter and two
  capability filters, security-relevant and to be unit-tested like `LoginFinalizer`.
- The bridge needs the `agent` query, the optional `expires_at` in the result, and the registry check from #73.
- `SECURITY-MODEL.md` gains the threats above, `ARCHITECTURE.md` the routes, the table and this ADR's row, in the
  implementation pull requests.
- Residual: credential revocation is not seen until the token expires; a route that only checks for a logged-in
  user is reachable with any scope; the delegation is as trustworthy as the issuer; prompt injection is the
  agent's to defend, and WordPress limits what a captured token is worth.

## Follow-up implementation issues

One pull request each, in this order; 5 can run in parallel with 1–4.

1. **Schema 5 and the tokens table.** `kind` and `requested_scope` on attempts, `{prefix}bloclabs_ssi_tokens`, a
   `TokenRepository`, purge of expired and revoked rows after the retention period. Files: `src/Database/Schema.php`,
   `src/Session/`, `src/Cron/PurgeExpired.php`, `uninstall.php`, tests.
2. **Agent routes and the header binding.** `POST /agent/initiate`, `POST /agent/token`, `DELETE /agent/token`,
   `HeaderBinding` behind an interface shared with `BrowserBinding`, `kind` checks on both route families, the shared
   rate limits, reconciliation on the token route. Files: `src/Rest/`, `src/Session/BrowserBinding.php`, tests
   (unit and integration, including the cross-kind refusals).
3. **Token issuance.** The common core of `LoginFinalizer` extracted; `TokenIssuer` with the resolution rules
   (`acts_for`, own key, never provision, opt-in), the login filters, the scope intersection, the token format and
   the one-token-per-attestation rule. Files: `src/Login/`, `src/Identity/`, `src/Config/Settings.php`, tests.
4. **Bearer authentication and scope enforcement.** The `determine_current_user`, `rest_authentication_errors`,
   `user_has_cap` and `map_meta_cap` filters, the denylist, HTTPS and REST-only checks, `last_used_at`, the refusal
   action. Files: `src/Auth/` (new), tests for every denied capability in A4.
5. **Bridge: the agent query and the credential's expiry.** The `agent` query profile and its start-up checks,
   `expires_at` in the result route, the registry pair (issuer, `vct`) for agent credentials once #73 is in.
   Files: `bridge/src/`, `bridge/README.md`, `docs/BRIDGE-API.md`, bridge tests.
6. **Profile screen, administration and automatic revocation.** *Agents may act for this account*, the token list
   with *Revoke* (for the user and for administrators), `wp bloclabs-ssi agent-tokens`, and the revocation hooks
   (`deleted_user`, `remove_user_from_blog`, unlink, `after_password_reset`). Builds on the 0.3 *Link a credential*
   screen. Files: `src/Admin/`, `src/Cli/Command.php`, `src/Plugin.php`, tests.
7. **Documentation and the end-to-end demo.** SECURITY-MODEL.md (A1–A14), ARCHITECTURE.md (routes, table, decision
   row), README (agent login no longer "planned"), and a reference agent client (Node, an SD-JWT VC holder library,
   a `did:key` or JWK) that logs in on the demo stack without a browser, which closes #64.
