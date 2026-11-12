# ActivityPods-managed ATProto signed repository bootstrap — isolated proof

**Status: NON-ACTIVATED EXPERIMENT.** This directory is deliberately **not** loaded by the ActivityPods Moleculer service loader, not wired into user signup, XRPC, Fedify or Solid permissions, and cannot become a production writer without an explicit reviewed integration. The store rejects bootstrap/verification unless 'fixtureOnly: true' is explicitly supplied.

This proof addresses one specific question from [cross-repo blocker #127](https://github.com/outlaw-dame/mastopod-federation-architecture/issues/127): **can we create a real signed v3 empty repository with a non-null MST CID, complete CAR, durable database head and native-event outbox in one transaction, then independently verify the persisted contents?** It does not claim ActivityPods is a production-complete PDS.

## Protocol and dependency decisions

- [ATProto Repository](https://atproto.com/specs/repository): version 3, data CID points to actual MST, 13-character TID rev, mandatory 'prev: null', secp256k1 SHA-256 signed unsigned CBOR, signature stored as raw 64-byte P1363 bytes.
- [ATProto TID](https://atproto.com/specs/tid): microseconds since epoch plus random 10-bit clock identifier.
- [ATProto Sync](https://atproto.com/specs/sync): signed commit is the first block and CAR root, followed by actual MST.
- Uses open-source @ipld/dag-cbor, multiformats, @ipld/car, and pg. Only exact direct package versions are declared in the local package.json. No home-grown CAR, CID or CBOR encoder.
- The valid empty MST is {l:null,e:[]}; this does not implement any non-empty record mutations or a full PDS.

## Authority, privacy and concurrency

- ActivityPods/SemApps Tier 1 must own managed AT repository state, identity and signing-key authority. The proof accepts a trusted signer callback but never imports or persists a private key.
- PostgreSQL is a **separate isolated candidate schema**, not an auth-account replacement or Solid/RDF source. Repo head, two DAG-CBOR blocks and immutable pending native-event outbox are inserted in **one transaction**. Redpanda publication is NOT implemented; an eventual publisher must retain and replay the event until acknowledged.
- Per-account transaction advisory locks, unique account/DID constraints, parameterized SQL, 5-second lock timeout and 10-second statement timeout prevent duplicate bootstrap. Signing completes **before** transaction locks are held.
- A replay independently verifies the persisted signed commit, CIDs, CAR and event outbox. There is no boolean-only readiness acceptance.
- Tests use a freshly generated disposable secp256k1 key held in memory, never printed or committed. The PostgreSQL test script refuses any non-loopback DSN, different database name or missing disposable marker.
- GitHub Actions installs dependencies with npm lifecycle scripts disabled in the isolated candidate directory. A generated lockfile is uploaded for review and must be retained for broader integration.

## Test scope

The dedicated workflow (see .github/workflows/paper-atproto-signed-repo-proof.yml) performs the following:

- Valid managed DID and sortable TID; negative DID, TID, signer and wrong public-key cases.
- Signed version-3 commit, mandatory 'prev: null', non-null root CID, canonical empty MST, complete two-block CAR, verified signature and independent SHA-256 CID.
- Eight competing signups for one account/DID produce exactly **one** stored repo, two blocks and one pending native-event outbox record.
- Identity uniqueness prevents a second account from claiming an existing DID and prevents changing a bound DID through bootstrap.
- A simulated failure after block storage but before outbox insertion rolls back the entire database transaction.
- Tampering with a stored MST invalidates the read-back until the correct block is restored.
- Safe default prevents running the proof as a production service.

## Not yet delivered — hard release blockers

Independent PLC DID resolution and key-document verification, Solid-OIDC/SAI delegated user grants, non-empty MST record writes/deletes, full CAR streaming at scale, distributed revision CAS beyond genesis, crash recovery between identitybinding and SQL, an event publisher with retries, PDS XRPC routes, relay/AppView interoperability, account deletion/rotation/export, SQL role hardening and production backup/restore.

## Future integration gates

1. Independently validate generated CAR/signature using a reference ATProto implementation.
2. Confirm PostgreSQL as **one Tier-1 managed repository writer** with no second Jena or sidecar writer; retain Jena for Solid/RDF.
3. Add a capability-protected Moleculer service that resolves the account's DID and signer internally. A client must never choose an arbitrary actor or private key.
4. Couple identitybinding finalization to cryptographically verified read-back and durable pending/retry state. Eliminate the existing placeholder root CID and revision from live signup.
5. Publish native AT events from the durable outbox with ordering/idempotency and outage recovery.
6. Connect exactly one XRPC and firehose network path and add real write/update/delete and external relay acceptance.
7. Enable production only after exact-head CI, multi-replica crash tests, security review, performance/cost and rollback approval.

This intentionally avoids the developer fork's unsigned fallback, generic master-token impersonation, process-local canonical repository, duplicate bridge and best-effort event publisher.


## Provider-authority bridge gate (stacked draft PR #141)

The non-activated 'provider-authority.mjs' and 'provider-moleculer.mjs' now connect this signed genesis proof to the *existing* ActivityPods provider contracts **without adding a production service or a second signer**.

- Source-of-truth split: protected Jena identitybindings own canonical WebID = ActivityPub actor, managed DID/handle, current key references and PDS identity. PostgreSQL owns the signed repository commit, MST blocks and native-event outbox. Neither side is silently overwritten on divergence.
- The provider adapter requires one authoritative current identitybinding for the exact account/DID/handle, a distinct rotation key, a managed local source, an independently resolved handle-to-DID match, the current PLC document's signing-key multibase, and matching PDS endpoint. A public caller cannot provide the signer, signing key, DID document or PDS authority.
- The only signing operation is 'signing.signAtprotoCommit' using ActivityPods key custody, after the trusted store builds the exact unsigned v3 commit; 'signing.getAtprotoPublicKey' returns public material only. The trusted Moleculer broker calls use a separate metadata context and never propagate the bridge's one-purpose capability into other services.
- The bridge action surface is internal only: 'bootstrapAndVerify', 'verifyReady' and read-only 'inspectRecovery'. It requires caller 'atproto-provisioning' AND a dedicated 32+ character provider capability. It also requires the disposable environment marker and always rejects NODE_ENV=production. No API alias or service-loader registration is added.
- Genesis signatures are canonical low-S per https://atproto.com/specs/cryptography. Read-back rejects noncanonical high-S signatures. The stored commit/MST/CAR/outbox are independently verified on each read-back, with a second identity check to reject mid-operation drift.
- Once PostgreSQL is committed but before RDF's repoRootCid/repoRev projection is recorded, 'inspectRecovery' reports recoveryRequired=true. The adapter **does not** blindly repair RDF, because distributed identitybinding CAS, revocation fencing and coordinated multi-replica reconciliation still need an independently reviewed protocol. 'verifyReady' fails closed until the RDF projection matches the signed PostgreSQL root and revision.
- The dedicated disposable PG18 workflow runs the original 8-way concurrency/transaction/CAR/reference tests and the provider bridge tests sequentially, including IDOR input rejection, PLC key drift, unsigned/mismatched signing, idempotent replay, recovery inspection and non-activated Moleculer authorization.

### Still blocking production integration

1. Explicitly review and safely register the Moleculer factory in a dedicated provider runtime after the current #134 and #140 signup readiness contract branches have been reconciled. Wire only a provider-minted capability; do not trust incoming request metadata. The current fixture-only store intentionally cannot be used in production.
2. Create a production-grade PostgreSQL schema/migration, least-privilege SQL role, replayable multi-replica saga and CAS/fencing of Jena binding updates. Production identity readiness must not rely on the current read-then-write gap.
3. Connect Solid-OIDC/SAI delegated grants and verify revocation cannot be bypassed. New account bootstrap also needs a carefully defined provider registration authority (as distinct from user-initiated writes).
4. Implement outbox publish/ack/retry with at-least-once delivery and deterministic idempotency; implement non-empty MST writes, repository reads/XRPC, relay interoperability, deletion, rotation and live DID PLC acceptance.
5. Confirm acceptable latency of repeated independent PLC/DNS verification (cache only with bounded staleness and revocation strategy), database costs, exact-head CI and disaster recovery. Do not activate this draft merely because proof tests pass.
