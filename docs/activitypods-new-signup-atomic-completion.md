# New Paper account: atomic completion boundary

**Status: NON-ACTIVATED INTEGRATION. Production signup is NOT released.**
Scope is strictly **new accounts**. No existing Solid/ActivityPub/ATProto
identity is imported, linked, re-keyed, repaired, or migrated.

## Authority

The ActivityPods provider is the only owner of account identity, WebID (equal
to ActivityPub actor URI), new `did:plc`, signing keys, native signed
repository, Solid-OIDC authorization and lifecycle. PostgreSQL is the
canonical operational signup ledger and managed-repository/consent store.
Jena Fuseki retains the user's Solid/RDF resources and protected projection.
Redis Streams and Redpanda do not determine authoritative account readiness.

The v4 additive SQL migration does **not** create a second account table.
It extends the existing account-bound signup operation journal introduced in
v2/v3. The normal `account.change(nextState:'ready')` method remains
**blocked** for all journal-backed new accounts.

## The completion transaction

The disposable `createDisposableSignupCompletion` candidate requires a
trusted, provider-injected callback. It cannot be called from a public HTTP
endpoint; the callback cannot be supplied as a signup request parameter.

Before acquiring a database connection, that callback must independently
reverify real current hosted-PDS XRPC functionality, protected Solid account
and identity binding, current PLC DID/handle/signing key and signed CAR, and
the owner-granted SAI permission. The test suite injects fixture evidence
and does not claim those live production validations are already integrated.

The completion worker then uses one bounded PostgreSQL transaction:

1. Lock the exact provider/account UUID row, then the exact HMAC-scoped
   signup operation row in consistent order. Require unchanged generation
   and `provisioning / evidence_sealed` state.
2. Recompute the historical v3 evidence digest (accepting its persisted
   pending/delivered outbox state) and compare it in constant time. Require
   the same DID, WebID, PDS, commit/root CID, revision and RDF fence.
3. Lock the same signed repository head and the applied PG->Jena projection
   intent. Require matching commit/root/revision/generation/fence.
4. Lock the canonical PostgreSQL managed identity and app consent in
   `FOR SHARE`, requiring active records, exact app/grant/DID, and current
   monotonic consent revision. A revocation `UPDATE` must wait for the
   completion transaction; a prior revocation denies completion.
5. Check the exact pending/delivered native event and absence of a
   terminally blocked historical event for that DID, via indexed lookups.
6. Update account to `ready` and signup journal to `ready` in the same
   transaction, persist only non-secret evidence and consent revision, and
   commit once. No external network call or key/PLC creation occurs while
   PostgreSQL row locks are held.

The writer does not grant an OAuth token or permit runtime authorization:
the disposable return value includes
`releaseAuthorized:false, canAuthenticate:false`.
Future signed record writes must independently verify canonical PostgreSQL
permission, even if the account was once `ready`.

A lost COMMIT response is **unknown**, not a rollback. The worker discards
that connection, does not retry identity side effects, and reconciles via
an indexed operation read; concurrent completion contenders either commit
once or return an idempotent, non-authorizing ready replay.

## Real PostgreSQL 18 proof

The CI fixture creates a disposable v1-v4 account journal, signed-repository
head/outbox/projection tables and canonical consent schema. It tests the
real transaction against: wrong hosted-PDS evidence, stale repository head,
revoked PG consent, revocation before the trusted proof completes, competing
completions, rollback after partial SQL work, a lost COMMIT acknowledgement,
and a revocation attempting to update a `FOR SHARE`-locked consent row.
It verifies no idle transactions remain and drops all synthetic schemas/roles.

The proof uses synthetic CIDs to isolate **transactional correctness**.
The separate signed-repository PG18/Fuseki integration verifies actual CAR,
MST, current DID key and native outbox. Combining them with real hosted PDS
and Solid-OIDC must be independently accepted before production activation.

## Still blocking production cutover

- Provide real trusted hosted-PDS XRPC/DID/handle and current owner/OIDC/SAI
  evidence into the completion callback. Fixture booleans have no production
  authority; the candidate refuses production regardless of environment
  flags.
- Register exactly one ActivityPods-owned signup coordinator with a
  least-privileged writer/reader/canonical-consent database credential set.
  An ordinary SPARQL connection must not be able to bypass identity/consent.
- Complete protected per-Pod RDF generation/CAS projection, durable
  compensating reconciliation for partially created external identities,
  signer key lifecycle and safe regrant constraints.
- Prove live PDS record create/update/delete and sync endpoints, signed CAR
  export/replay, outbox delivery/fencing, owner auth, account recovery and
  host relocation from independent clients, on multiple instances.
- Repeat independent four-worker kill/failover, simultaneous revoke/commit,
  backup/PITR, database pool saturation, p95/p99 latency and operating cost
  tests on the integrated production candidate. Verify actual deployable
  environment configuration and rollback.
- Only after review and exact-head acceptance may the source-controlled
  signup and native-storage release fuses be considered for removal.

The new v4 migration is disposable evidence, not an instruction to run it
against an existing deployment.
