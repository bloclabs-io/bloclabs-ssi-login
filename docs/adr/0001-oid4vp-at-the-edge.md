# ADR 0001: OpenID4VP at the edge, FireFly behind it

**Status:** accepted, 2026-11-03

## Question

Should WordPress expose an OpenID for Verifiable Presentations interface directly, backed by FireFly, or should
FireFly's own messaging and event streams carry the credential request? And where does DIDComm fit?

## Facts (checked 2026-11-03)

- **OpenID4VP 1.0 is Final** (9 July 2025). DCQL is its only query language; cross-device uses `direct_post` or
  `direct_post.jwt`; the client id carries a prefix (`x509_san_dns:`, `x509_hash:`, `verifier_attestation:`,
  `decentralized_identifier:`, `redirect_uri:`, `openid_federation:`).
- **HAIP 1.0 is Final** (December 2025) and profiles OpenID4VP for SD-JWT VC and mdoc. EU wallets, Android
  Credential Manager and the W3C Digital Credentials API (Chrome 141+, Safari 26 for mdoc) all build on OpenID4VP.
- **SD-JWT is RFC 9901**; SD-JWT VC is in IESG evaluation; VC Data Model 2.0 is a W3C Recommendation (May 2025).
- **Hyperledger Aries is archived** (2025). ACA-Py and Credo moved to the OpenWallet Foundation; DIDComm
  present-proof lives on mainly in AnonCreds ecosystems.
- **FireFly v1.5.0 has no VC, DID-resolution or OpenID4VP support.** Its messaging is org-to-org between members of
  a multiparty network, and is unavailable in gateway mode (FF10414).

## Options

1. **OpenID4VP inside WordPress (PHP).** WordPress would sign request objects, hold X.509 or DID keys, parse
   SD-JWT and mdoc, check key binding and status lists. That is a large cryptographic surface in a CMS, keys in the
   WordPress database, and young PHP libraries. It contradicts the "lightweight footprint" goal.
2. **FireFly messaging to the wallet.** Wallets do not speak FireFly. A phone is not a FireFly organisation or node,
   and gateway mode has no messaging at all.
3. **DIDComm.** Connection-oriented, needs mediators, and few mainstream wallets present that way today.
4. **OpenID4VP in a verifier sidecar ("bridge"); FireFly carries the outcome.** Chosen.

## Decision

The wallet-facing protocol is OpenID4VP 1.0 (HAIP where possible), implemented by a dedicated verifier behind the
[bridge API](../BRIDGE-API.md). FireFly is the trust and event backbone: the bridge records each decision on chain
through FireFly, and FireFly streams it to WordPress.

## Consequences

- WordPress never parses a credential and holds no protocol keys.
- The plugin is protocol-agnostic past the bridge: a Credo-based bridge could add DIDComm without plugin changes.
- One more service to run. The reference bridge targets walt.id verifier-api2 in Docker.
