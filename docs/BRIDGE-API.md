# Verifier bridge API

The bridge is a small service next to an OpenID4VP verifier. It is the only component that touches credentials.
WordPress calls it twice per login; wallets call its OpenID4VP endpoints; it calls FireFly once per decision.

Authentication between WordPress and the bridge: a static `Authorization` header (setting
`verifier_auth_header`) over a private network, or mTLS at a proxy.

## `POST /v1/presentation-requests`

Opens a presentation request for one login attempt.

Request:
```json
{
  "correlation_id": "3575e334…7fea",
  "nonce": "q2F8…",
  "query": "default",
  "expires_at": "2026-11-03T12:00:00Z"
}
```
- `correlation_id`: 64 hex characters. The bridge echoes it on chain and must never accept the same one twice.
- `nonce`: use it as the OpenID4VP `nonce` when the underlying verifier lets the caller choose. If not, record the
  verifier's own nonce; WordPress's security does not depend on this value, because `correlation_id` binds the
  attempt.
- `query`: the name of a DCQL query configured in the bridge (for example "a PID with family_name and
  birth_date", or "an employee credential from issuer X"). WordPress never sends DCQL itself.
- `expires_at`: refuse wallet responses after this time.

Response `201`:
```json
{
  "id": "vr_01HF…",
  "wallet_url": "openid4vp://?client_id=x509_san_dns:verifier.example.com&request_uri=https%3A%2F%2Fverifier.example.com%2Fr%2Fvr_01HF",
  "dc_api": null
}
```
- `wallet_url`: what the browser shows as a QR code and opens as a same-device link. Allowed schemes are
  `openid4vp` and `https` unless the site widens them.
- `dc_api`: optional, reserved for the Digital Credentials API path (roadmap): the object to pass to
  `navigator.credentials.get({digital: {requests: [...]}})`.

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
  issuer-scoped identifiers use `issuer + "|" + sub`. It must be the value committed on chain.
- `presentation_hash`: lowercase hex SHA-256 of the presentation exactly as received (the `vp_token` value).
- `claims`: only what the query disclosed.

Answer `409` while the request is undecided, `404` once the result has expired. Keep results for at least the
attempt lifetime plus a minute, then delete them.

## What the bridge must do on each wallet response

1. Validate the presentation per OpenID4VP 1.0 and the credential format: issuer signature, holder binding
   (SD-JWT key-binding JWT or mdoc device signature) over the expected `nonce` and audience, validity period.
2. Check the issuer against its trust list and the credential's status (IETF Token Status List or the format's
   equivalent).
3. Evaluate the DCQL query.
4. Compute `subjectCommitment = sha256(correlation_id + ":" + subject_id)` and `presentationHash`.
5. Call `attest(correlationId, result, subjectCommitment, presentationHash)` through FireFly, signing with an
   address the contract owner authorised. Rejections are attested too (`result = 2`, commitments may be zero).
6. Only then mark the result readable.

## Choosing a verifier

| Verifier | Fit |
|---|---|
| [walt.id verifier-api2](https://github.com/walt-id/waltid-identity) (Kotlin, Apache-2.0) | **Reference choice.** OpenID4VP 1.0, DCQL, SD-JWT VC and mdoc, Digital Credentials API sessions, REST session API with callbacks |
| [EUDI verifier endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint) (Kotlin) | Strict HAIP profile. Its README says it is not for production |
| [Credo](https://github.com/openwallet-foundation/credo-ts) (TypeScript) | When the bridge itself should be TypeScript; also speaks DIDComm if that is ever needed |

The bridge runs as its own process, so Apache-2.0 verifier code never links into GPL WordPress code.
