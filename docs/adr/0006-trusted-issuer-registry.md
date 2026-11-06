# ADR 0006: Trusted issuers in an on-chain registry, read by the bridge through FireFly

**Status:** accepted, 2026-11-06 (#74)

## Question

Which issuers may log someone in, for which credential types, and where is that list kept? Who may change it, what
does a change leave behind, and what part of credential validation stays off chain?

## Facts (checked 2026-11-06)

- The original brief asked FireFly to handle "decentralized identity, credential validation, and event-streaming".
  FireFly v1.5.0 has no Verifiable Credential, DID-resolution or OpenID4VP support
  ([ADR 0001](0001-oid4vp-at-the-edge.md)), so credential validation went to the verifier sidecar and only the verdict
  reached the chain ([ADR 0004](0004-on-chain-attestation.md)). The trust decision, "is this an issuer we accept?",
  stayed off chain with it.
- In 0.2 the trust list is a walt.id `allowed-issuer` policy inside `BRIDGE_QUERIES`: a list of issuer identifiers in an
  environment variable of the bridge container, one list per query ([bridge/README.md](../../bridge/README.md)).
  Changing it means redeploying the bridge. Nothing records who changed it, when, or what the list was when a given
  login was attested: the chain says "verified, by this verifier address" and no more. An issuer in that list is
  trusted for every credential type the query names.
- An SD-JWT VC carries its issuer in `iss` and its type in `vct`; both are required claims. The verifier checks the
  issuer's signature with keys it resolves from `iss` (a DID document, the issuer's `/.well-known/jwt-vc-issuer`
  metadata, or an `x5c` chain). walt.id does this in its `signature` policy, which runs whether or not an
  `allowed-issuer` policy is configured.
- A FireFly contract API exposes a contract's `view` functions under `/apis/{name}/query/{method}`. A query is a read
  through the connector (`eth_call`): nothing is signed, nothing is written to the chain, so it leaves no per-login
  trace there.
- The contract (#71) and the bridge check (#73) were built in parallel against one interface the code owner fixed
  in advance, reproduced below, and both are on `main`. A change to the interface goes back to the code owner first.

## Options

| Option | Problem |
|---|---|
| 1. Keep the list in the bridge configuration (status quo) | Governance by redeploy, no record of changes, and the audit trail cannot say under which trust list a login was accepted. The brief asked for the trust decision to be on chain. |
| 2. An off-chain trust list: OpenID Federation trust chains, an ETSI TS 119 612 trusted list, EBSI's Trusted Issuers Registry | Standard and interoperable, but each belongs to a federation or a government ecosystem this project is not part of; it adds a fetch, a cache and a second signing authority to the bridge, and the decision is still recorded somewhere other than where the verdicts are. A registry on chain can later be fed from such a list. |
| 3. Check the issuer inside the attestor (`attest` takes the issuer and reverts when it is untrusted) | Puts the issuer and the credential type of every login into a transaction, public and permanent, which narrows down who logged in (security model threat 8). It also turns a rejection into a failed transaction instead of an attested `result = 2`. |
| 4. The bridge reads the chain itself (a JSON-RPC client and ABI encoding) | A runtime dependency, or hand-written ABI code, in the component [ADR 0005](0005-bridge-stack.md) keeps dependency-free; a second chain connection and a second set of chain credentials to protect, when FireFly already fronts the chain for `attest` and decodes outputs. |
| 5. A registry contract, read by the bridge through FireFly's query API before it attests | Chosen. |

## Decision

### The contract

`contracts/TrustedIssuerRegistry.sol` (#71) implements exactly the interface the code owner fixed for #71 and #73:

```solidity
contract TrustedIssuerRegistry {
    event IssuerSet(bytes32 indexed key, string issuer, string vct, bool trusted, address indexed by);
    // key = keccak256(abi.encode(issuer, vct)); owner + two-step ownership transfer as in SsiLoginAttestor
    function setIssuer(string calldata issuer, string calldata vct, bool trusted) external; // onlyOwner
    function isTrusted(string calldata issuer, string calldata vct) external view returns (bool);
}
```

- **Trust is a pair, `(issuer, vct)`, not an issuer.** An issuer trusted for one credential type (an employee badge) is
  not thereby trusted for another (an administrator role). The pair mirrors what a DCQL query asks for (`vct_values`)
  and what the credential carries (`iss`, `vct`). Both strings are compared exactly as the credential carries them; a
  registry entry is the issuer identifier and the `vct` verbatim, with no normalisation.
- **Unknown means untrusted.** `isTrusted` returns `false` for any pair that was never set, and `setIssuer(…, false)`
  withdraws trust without deleting history.
- **Every change is an event.** `IssuerSet` records the pair, its new state and the caller's address, so the chain holds
  the whole history of the list, and a FireFly listener on it can alert an operator.
- **Entries are public.** The event carries both strings verbatim, so the registry holds issuer identifiers and
  credential types, which are policy, and never a holder identifier or a claim.
- **Only the owner changes it,** with the same two-step ownership transfer as `SsiLoginAttestor`. The owner is an
  operator key held away from the bridge: the bridge's `FIREFLY_SIGNING_KEY` is never the registry owner, so a
  compromised bridge can still attest but cannot widen the trust list. WordPress holds no chain key at all.
- One registry per chain and FireFly namespace, published as the FireFly contract API `trusted-issuer-registry`.
  Sites that share a bridge share its trust list; a different list is a second registry under a second API name.

### The check in the bridge

When `FIREFLY_REGISTRY_API` is set (#73), the bridge asks `POST /apis/trusted-issuer-registry/query/isTrusted` with
`{"input": {"issuer": "…", "vct": "…"}}` for every presentation the verifier reports as `SUCCESSFUL`, before it
attests:

- **The pair comes from the presented credential,** after the verifier has checked its signature, holder binding and
  validity: the credential's issuer and `vct` as walt.id parsed them, never from the query configuration and never
  from anything the wallet sent unsigned. A credential that names no issuer or no `vct` cannot be in the registry, so
  it is untrusted without a query.
- **`true` is trust, `false` is an untrusted pair,** attested as a rejection (`result = 2`), exactly as a presentation
  walt.id refused is.
- **No answer fails closed.** An unreachable FireFly, an unknown API or an `output` that is not a boolean is not a
  decision: the bridge retries a transient failure as it does for `attest`, and if the registry still cannot answer
  there is no attestation at all. The bridge marks the request failed (its result route answers `failed`) and, with
  nothing attested to deliver, the attempt expires in WordPress. The bridge never attests `verified` for a credential
  whose issuer it could not check, and never attests `rejected` for a credential nobody rejected.
- **When `FIREFLY_REGISTRY_API` is unset** the bridge behaves as in 0.2: issuer trust is whatever `allowed-issuer`
  policy the query carries, and nothing else.

The check is a read, not a transaction: the issuer and type of a login never reach the chain, and `LoginAttested`
keeps its commitments-only payload (ADR 0004).

### What stays off chain, and why

| Stays in the verifier (walt.id) or the bridge | Why not on chain |
|---|---|
| Issuer signature verification | Needs the issuer's current keys, which issuers publish under their own identifier and rotate; the chain cannot verify an SD-JWT, and a copy of the keys would go stale. The registry holds identifiers, not keys: it says *whom* to trust, the signature check says *whether this credential is really theirs*. Both must pass. |
| Holder binding (the key-binding JWT over the verifier's nonce and audience) | Per-session values the chain never sees; the verifier created the nonce. |
| Validity period and revocation (IETF Token Status List, walt.id `credential-status`) | Status changes often and is published by the issuer; a chain copy would lag, and checking it is one fetch of the issuer's list. Revoking one credential is the issuer's decision; the registry governs the issuer, not its credentials. |
| The DCQL query: which type to ask for and which claims to disclose | Per-site policy in the bridge configuration; it does not change who is trusted. |
| The credential's claims and the holder's identity | Never on chain (ADR 0004, security model threat 8). |

### Migration from the `allowed-issuer` policy

1. Deploy the registry and publish its FireFly API `trusted-issuer-registry`: steps 6 to 8 of
   [FIREFLY-FLOW.md](../FIREFLY-FLOW.md) "One-time setup". The deployer's key becomes the owner; transfer ownership
   to the operator key that will govern the list when that is a different key.
2. For every query in `BRIDGE_QUERIES`, invoke `setIssuer(issuer, vct, true)` through that API for each issuer in its
   `allowed_issuer` list and each `vct` in its `vct_values`. Check each pair with `isTrusted` through the query API.
3. Set `FIREFLY_REGISTRY_API=trusted-issuer-registry` on the bridge and restart it. From then on every verified
   presentation is checked against the registry.
4. Remove the `allowed-issuer` policy from the queries, so that the registry is the one place where issuer trust is
   set and a change there takes effect without redeploying the bridge. Keep `signature`, `expiration`, `not-before`
   and `credential-status`: those are the checks the registry does not replace. With both set, an issuer must pass
   both ([bridge/README.md](../../bridge/README.md)), which is harmless but means every change has to be made twice.

Withdrawing trust (`setIssuer(…, false)`) stops new logins with that pair from the next presentation on. It does not
end sessions already issued, and it does not unlink accounts linked through that issuer; the `identities` table keeps
the issuer, so an operator can find and unlink them.

## Consequences

- The trust decision is auditable like the verdicts: anyone with the chain can list `IssuerSet` events and say which
  pairs were trusted when a given `LoginAttested` was emitted. Deployment history no longer has to be the record.
- Issuer trust changes without touching the bridge: one `setIssuer` transaction by the owner, no redeploy.
- Latency: one FireFly query per verified presentation, between the verifier's answer and `attest`. It is an
  `eth_call`, milliseconds, not a block.
- Availability: FireFly is now needed to verify, not only to attest. Credential login already fails closed when
  FireFly is down (no attestation, no login), so the check adds no new dependency, only a second call on the same one.
- The registry owner key is a new secret with its own blast radius: whoever holds it decides which issuers log people
  in. The security model lists it (threats 22 and 23) with its mitigations: custody away from the bridge, two-step
  transfer, an event per change.
- The `issuer` string WordPress receives from the bridge is still authenticated HTTP data, not an on-chain fact
  ([ARCHITECTURE.md](../ARCHITECTURE.md), trust boundary 5). What the chain proves is narrower: with the registry on,
  a `LoginAttested` with `result = 1` was emitted only after the bridge found the credential's `(issuer, vct)` trusted.
- Agent credentials ([ADR 0007](0007-agent-login.md)) are governed in the same registry: the issuers of agent
  credentials are set, withdrawn and audited in one place.
- Not decided here: a per-site trust list behind one bridge, a registry fed from an external trust list (OpenID
  Federation, an ETSI trusted list), and a UI or WP-CLI command to manage the registry. Each is a follow-up issue.
