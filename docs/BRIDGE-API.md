# Verifier bridge API

The bridge is a small service next to an OpenID4VP verifier. It is the only component that touches credentials.
WordPress calls it twice per login; wallets call its OpenID4VP endpoints; it calls FireFly once per decision.

The reference implementation is [`bridge/`](../bridge/README.md), TypeScript on walt.id verifier-api2. Notes marked
*Reference bridge* say what it does where this contract leaves the choice to the implementation.

Authentication between WordPress and the bridge is **required**: a static `Authorization` header (setting
`verifier_auth_header`, best pinned as `BLOCLABS_SSI_VERIFIER_AUTH_HEADER`) over a private network. WordPress
refuses to start a login without it. *Reference bridge:* the header is `Bearer <BRIDGE_AUTH_TOKEN>`, and the
bridge refuses to start without a token. Serve these two routes on the private network only; the wallet-facing host
exposes nothing but the OpenID4VP endpoints, because the result route returns claims and its id appears in the
QR code.

## `POST /v1/presentation-requests`

Opens a presentation request for one login attempt.

Request:
```json
{
  "correlation_id": "3575e334…7fea",
  "nonce": "q2F8…",
  "blinding_secret": "9f3a…c41e",
  "query": "default",
  "expires_at": "2026-11-03T12:00:00Z"
}
```
- `correlation_id`: 64 hex characters. The bridge echoes it on chain and must never accept the same one twice.
- `nonce`: use it as the OpenID4VP `nonce` when the underlying verifier lets the caller choose. If not, record the
  verifier's own nonce; WordPress's security does not depend on this value, because `correlation_id` binds the
  attempt. *Reference bridge:* walt.id generates the OpenID4VP nonce and state itself; WordPress's value is kept
  with the request and not used.
- `blinding_secret`: 64 hex characters, random per attempt. It enters `subjectCommitment` and nothing else:
  never put it on chain, in a log, in the wallet request or in the verifier session. WordPress keeps it on the
  attempt row to recompute the commitment at completion.
- `query`: the name of a DCQL query configured in the bridge (for example "a PID with family_name and
  birth_date", or "an employee credential from issuer X"). WordPress never sends DCQL itself.
- `expires_at`: refuse wallet responses after this time. *Reference bridge:* passed to walt.id as the session's
  `expiration_date`; the bridge also refuses to attest a decision that arrives after it.

Response `201`:
```json
{
  "id": "vr_01HF…",
  "wallet_url": "openid4vp://?client_id=x509_san_dns:verifier.example.com&request_uri=https%3A%2F%2Fverifier.example.com%2Fr%2Fvr_01HF",
  "dc_api": {
    "requests": [{"protocol": "openid4vp-v1-unsigned", "data": {"response_type": "vp_token", "response_mode": "dc_api", "nonce": "…", "dcql_query": {"…": "…"}, "client_metadata": {"…": "…"}}}],
    "response_url": "https://verifier.example.com/verification-session/vr_01HF-dc/response"
  }
}
```
- `id`: the bridge's id for the request, at most 191 characters. WordPress stores it and sends it back on the
  result route.
- `wallet_url`: what the browser shows as a QR code and opens as a same-device link. Allowed schemes are
  `openid4vp` and `https` unless the site widens them.
- `dc_api`: the same request for the browser's [Digital Credentials API](https://www.w3.org/TR/digital-credentials/),
  or `null` when the bridge cannot offer one (see [the Digital Credentials API path](#the-digital-credentials-api-path)
  below). WordPress passes the object to the login page unchanged.
  - `requests`: the `requests` of `navigator.credentials.get({digital: {requests}})`, each `{"protocol", "data"}` as
    OpenID4VP 1.0 appendix A defines them (`openid4vp-v1-unsigned` with the request parameters as `data`, or
    `openid4vp-v1-signed` with `{"request": "<JWT>"}`). A wallet answers one of them.
  - `response_url`: where the login page posts the wallet's answer, as JSON `{"protocol", "data"}` (the
    `DigitalCredential` the browser returned); `data` holds `vp_token`, or `response` when the answer is encrypted.
    An `https` URL; the page refuses anything else, except plain `http` when the page itself is plain `http`
    (a localhost test stack). The route must answer CORS for the login page's origin: the page sends no cookie
    and no Authorization header, the origin binding in the presentation is the authentication.
- *Reference bridge:* `id` is a UUID the bridge chose as the walt.id session id; `wallet_url` is walt.id's
  `bootstrapAuthorizationRequestUrl` (the `request_uri` form); `dc_api` is set when `BRIDGE_DC_API_ORIGINS` is
  configured, and `null` otherwise or when its second session could not be opened (logged, the QR code stands
  alone).

## The Digital Credentials API path

Where the browser implements the Digital Credentials API (Chrome 141+ on Android and desktop, Safari 26 for mdoc)
and the bridge answered with `dc_api`, the login page asks the wallet through the browser instead of showing the
QR code, on the user activation of the "Log in with a digital credential" click, which the API requires. The
browser hands the request to the wallet together with the page's origin, and the wallet binds its presentation
to that origin (the key-binding JWT's `aud` is `origin:https://site.example`), so a request relayed to another
page cannot log this one in: this is the same-device answer to threat 1 of [SECURITY-MODEL.md](SECURITY-MODEL.md).
The page then posts the answer to `response_url` and keeps polling `/status` as in the cross-device flow; the
decision reaches WordPress through the chain and `/complete` exactly as before, under the same `correlation_id`,
so WordPress itself has no second code path. If the holder dismisses the browser's prompt, no wallet answers, a
protocol is refused (`DigitalCredential.userAgentAllowsProtocol`), or the answer cannot be delivered, the page
falls back to the QR code and the wallet link; "Cancel" aborts the prompt. Without the API, or with `dc_api`
`null`, nothing changes.

What the bridge must do for `dc_api`:

1. Bind the request to the login page's origin (`expected_origins`, configured, never taken from the request),
   and verify the holder binding against that origin, not against a response URI.
2. Treat the browser-bound request and the QR code as one attempt: the first answer decides, is attested once
   under the attempt's `correlation_id` (step 4 and 5 below), and the other request can no longer change the
   outcome. The result route reads the same way whichever path answered.
3. Keep the browser-facing response route on the public host with the OpenID4VP endpoints, answering CORS for
   the login page's origin only; it needs no bridge credential, and the login page sends none.

*Reference bridge:* a second walt.id session of flow type `dc_api_openid4vp` per request, with the same query,
expiry, retention and webhook as the cross-device one, bound to `BRIDGE_DC_API_ORIGINS`; the request is walt.id's
own wrapper from `GET /verification-session/{id}/request` (`{"digital": {"requests": [...]}}`), unsigned with the
response in clear (`response_mode: dc_api`) unless walt.id's configuration signs or encrypts, and `response_url`
is `VERIFIER_PUBLIC_URL/verification-session/{id}/response`, walt.id's response route, which takes the JSON
answer and allows every origin in CORS (1.2.0). Either session's webhook rings the bridge under that session's
id; whichever settles first is attested, with `dcApi: true` in the log line when it was the browser's session.

## `GET /v1/presentation-requests/{id}/result`

Called by WordPress at completion, after the chain has said "verified".

Response `200`:
```json
{
  "subject_id": "did:jwk:eyJrdHkiOi…",
  "issuer": "did:web:issuer.example.com",
  "presentation_hash": "ced03b89…69f5",
  "claims": {"given_name": "Ada", "email": "ada@example.com"}
}
```
- `subject_id`: a stable holder identifier. For SD-JWT VC use the holder key (`cnf`) thumbprint or a DID; for
  issuer-scoped identifiers use `issuer + "|" + sub`. It must be the value committed on chain. *Reference bridge:*
  the RFC 9278 thumbprint URI of `cnf.jwk` (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:…`), or the DID behind
  `cnf.kid` without its fragment.
- `issuer`: the credential issuer, or `null` when the credential names none.
- `presentation_hash`: lowercase hex SHA-256, 64 characters with no `0x` prefix (WordPress strips one, but
  writes none), of the RFC 8785 canonical JSON of the `vp_token` as the verifier
  parsed it: the JSON object that maps each credential-query id to its list of presentations, with object keys
  sorted, no whitespace and JSON string escaping. For one presentation that is
  `sha256('{"<credential query id>":["<presentation>"]}')`. It is not a hash of the bytes the wallet posted:
  walt.id keeps the parsed object, not those bytes, and WordPress only compares this value with the one on chain,
  both written by the bridge, so the definition has to be stable rather than byte-exact. *Reference bridge:*
  `canonicalJson()` and `presentationHash()` in `bridge/src/crypto.ts`, pinned by fixed vectors in
  `bridge/test/crypto.test.ts`, so a verifier upgrade that changes the parsed shape fails a test instead of
  silently changing the hashes on chain.
- `claims`: only what the query disclosed. *Reference bridge:* the values at the DCQL claim paths the query asked
  for; for a credential query without `claims`, every disclosed claim except the registered ones.

Answer `409` while the request is undecided, `404` once the result has expired. *Reference bridge:*
`409 {"error":"pending"}` until FireFly accepted the attestation, `200` for a verified login,
`404 {"error":"rejected"}` after a rejection, `404 {"error":"failed"}` when no attestation could be made, and
`404 {"error":"not_found"}` once the request was deleted. WordPress retries `409`, `408`, `425`, `429`, any `5xx`
and an unreachable bridge: the attempt stays verified and the browser retries `/complete` a few times, so the
bridge may attest a moment before it serves the result. `404` and every other `4xx` fail the attempt for good, as
does a `200` whose body WordPress cannot use, so answer `409`, never `404`, until the result is readable. Keep
results for at least the attempt lifetime plus a minute, then delete them.

## What the bridge must do on each wallet response

1. Validate the presentation per OpenID4VP 1.0 and the credential format: issuer signature, holder binding
   (SD-JWT key-binding JWT or mdoc device signature) over the expected `nonce` and audience, validity period.
2. Check the issuer against its trust list and the credential's status (IETF Token Status List or the format's
   equivalent).
3. Evaluate the DCQL query.
4. Compute `subjectCommitment = sha256(correlation_id + ":" + blinding_secret + ":" + subject_id)` (lowercase hex
   correlation id) and `presentationHash`.
5. Call `attest(correlationId, result, subjectCommitment, presentationHash)` through FireFly, signing with an
   address the contract owner authorised, with an idempotency key derived from `correlation_id`, so that a retried
   call can never attest the same attempt twice (FireFly's `idempotencyKey`; a duplicate answers `409 FF10431`).
   Rejections are attested too (`result = 2`, commitments may be zero). A wallet's OpenID4VP error response (the
   holder declined) is a rejection as well, with a zero presentation hash; [FIREFLY-FLOW.md](FIREFLY-FLOW.md) says
   why it is attested rather than left to expire.
6. Only then mark the result readable.

## Verifier callbacks (reference bridge)

walt.id posts every session update to `POST /v1/verifier-callbacks/{session}` on the bridge, with a bearer token
the bridge generated for that request; `{session}` is the verifier session id, the request's own id for the
cross-device session and a second id for its Digital Credentials API session. The bridge treats the call as a
doorbell: it ignores the body, re-reads the session with `GET /verification-session/{session}/info`, and acts
only on `SUCCESSFUL` or `FAILED`. The route is for the verifier alone and sits on the private network with the
two WordPress routes.

## Choosing a verifier

| Verifier | Fit |
|---|---|
| [walt.id verifier-api2](https://github.com/walt-id/waltid-identity) (Kotlin, Apache-2.0) | **Reference choice, used by [`bridge/`](../bridge/README.md).** OpenID4VP 1.0, DCQL, SD-JWT VC and mdoc, Digital Credentials API sessions, REST session API with callbacks |
| [EUDI verifier endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint) (Kotlin) | Strict HAIP profile. Its README says it is not for production |
| [Credo](https://github.com/openwallet-foundation/credo-ts) (TypeScript) | When the bridge itself should be TypeScript; also speaks DIDComm if that is ever needed |

The bridge runs as its own process, so Apache-2.0 verifier code never links into GPL WordPress code.
