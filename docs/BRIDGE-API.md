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
  "dc_api": null
}
```
- `id`: the bridge's id for the request, at most 191 characters. WordPress stores it and sends it back on the
  result route.
- `wallet_url`: what the browser shows as a QR code and opens as a same-device link. Allowed schemes are
  `openid4vp` and `https` unless the site widens them.
- `dc_api`: optional, reserved for the Digital Credentials API path (roadmap): the object to pass to
  `navigator.credentials.get({digital: {requests: [...]}})`.
- *Reference bridge:* `id` is a UUID the bridge chose as the walt.id session id; `wallet_url` is walt.id's
  `bootstrapAuthorizationRequestUrl` (the `request_uri` form); `dc_api` is always `null`.

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

walt.id posts every session update to `POST /v1/verifier-callbacks/{id}` on the bridge, with a bearer token the
bridge generated for that session. The bridge treats the call as a doorbell: it ignores the body, re-reads the
session with `GET /verification-session/{id}/info`, and acts only on `SUCCESSFUL` or `FAILED`. The route is for
the verifier alone and sits on the private network with the two WordPress routes.

## Choosing a verifier

| Verifier | Fit |
|---|---|
| [walt.id verifier-api2](https://github.com/walt-id/waltid-identity) (Kotlin, Apache-2.0) | **Reference choice, used by [`bridge/`](../bridge/README.md).** OpenID4VP 1.0, DCQL, SD-JWT VC and mdoc, Digital Credentials API sessions, REST session API with callbacks |
| [EUDI verifier endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint) (Kotlin) | Strict HAIP profile. Its README says it is not for production |
| [Credo](https://github.com/openwallet-foundation/credo-ts) (TypeScript) | When the bridge itself should be TypeScript; also speaks DIDComm if that is ever needed |

The bridge runs as its own process, so Apache-2.0 verifier code never links into GPL WordPress code.
