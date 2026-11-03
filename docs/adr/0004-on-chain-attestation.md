# ADR 0004: Attest each decision with a contract event

**Status:** accepted, 2026-11-03; amended 2026-11-03 (blinding secret, #25)

## Question

What exactly does FireFly carry from the verifier to WordPress?

## Options

1. **The bridge calls WordPress directly.** Simple, but nothing outside the two parties records the decision, and
   FireFly is not involved.
2. **A FireFly broadcast or private message with the result.** Needs multiparty mode (not available in gateway
   mode), and a broadcast publishes its payload to shared storage.
3. **A custom contract event, `LoginAttested`.** Chosen.

## Decision

`contracts/SsiLoginAttestor.sol` emits `LoginAttested(correlationId, result, subjectCommitment, presentationHash,
verifier)`. Only addresses the owner authorised can emit it. The bridge invokes it through a FireFly contract API;
a FireFly contract listener turns it into a `blockchain_event_received` event, which the webhook subscription
delivers.

Only commitments go on chain:
- `correlationId`: random per attempt;
- `subjectCommitment = sha256(hex(correlationId) ":" blindingSecret ":" subjectId)`, where `blindingSecret` is a
  random per-attempt secret that WordPress generates, stores on the attempt and shares with the bridge only. It
  never reaches the chain or the browser. The correlation id alone would not do: it is a topic of the same event,
  so with it anyone could test guessed subject ids (a `did:web`, DIDs from registries) against every attestation.
  With the secret, one person's logins cannot be linked and a guess cannot be checked by reading the chain (#25);
- `presentationHash = sha256(vp_token)`.

## Consequences

- Every login decision is independently auditable: who decided (verifier address), when (block), and a binding to
  what WordPress was later told.
- WordPress checks the bridge's HTTP answer against the on-chain commitments before logging anyone in.
- Latency: one block. On Besu QBFT with 2-second blocks, `attest` to readable event took 2.9 s.
- Gas: negligible on a private chain; the contract stores nothing per login.
