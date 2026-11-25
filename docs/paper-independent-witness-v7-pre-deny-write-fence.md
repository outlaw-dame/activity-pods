# Witness v7 — prepared immutable PRE-DENY and signed-PDS writer fence

**Status: NONACTIVATED candidate, production signup/PDS OAuth remains CLOSED.**

## Critical security property

An independently committed PRE-DENY must stop new signed-PDS reservations
**before** a revoker tries to change canonical PostgreSQL, Redis, native
Jena/SAI or token-family state. An ACTIVE head read made before an
independent denial can race a signing worker; it is not a durable permit.

This patch adds `paper-oauth-external-restore-witness-v7-pre-deny-writer-fence.sql`
for the **separate witness PostgreSQL 18 failure domain only**, after
witness v1 through v6 and with **zero historical signed-write intents**.
No production service auto-migrates it, no new LOGIN is created, and
source-controlled release remains CLOSED.

## What is implemented

- **One-way PREPARE CAS:** Restricted `paper_oauth_witness_pre_deny_preparer`
  may call only the `prepare_pre_deny` function. It locks the exact
  independent owner/client witness epoch and records the immutable
  denial operation, canonical credential epoch, SAI revision and scope
  digest. The same operation may be re-read after an uncertain
  acknowledgment. A new operation, different grant/owner or credential
  epoch cannot silently replace it. No automatic abort or expiry exists.
- **New signed-PDS reservations denied:** A `BEFORE INSERT` trigger
  on signed-write intents takes `FOR SHARE` on the same independent epoch
  row. PREPARE takes `FOR UPDATE`. Thus a writer that wins first records
  an existing pending intent which must settle; a PREPARE that wins first
  prevents every later reservation. Direct INSERT remains forbidden to
  the writer role; the trigger is additional defense in depth.
- **Read authority denied immediately:** The independent witness
  `verify` and `active_checkpoint` queries return no active authority
  once a denial is prepared, even before the WORM object has been
  archived. This is fail-closed: a lost S3 receipt or signer ACK cannot
  restore permission simply because an archive call timed out.
- **Exact immutable receipt:** The restricted,
  separately credentialed `paper_oauth_witness_pre_deny_attestor` can
  read the exact canonical, pseudonymized `pre-deny/v1` JSON bytes in
  the same field order as the established JavaScript coordinator and
  S3 COMPLIANCE parser. It must independently verify the Object Lock
  object version, retention and exact bytes, then seal this **same**
  receipt SHA256 through a dedicated SQL function. The witness
  database cannot prove its own independent archive; it only
  validates the bytes the outside attestor claims to have retained.
- **Strict revocation prerequisite:** The existing witness revoker
  `block` entry point now requires the exact prepared operation and
  sealed WORM receipt; the earlier v5 trigger additionally requires
  **all** signed-PDS pending and resolved outcome receipts to be
  independently sealed. A lost commit or unresolved signed write does
  not age out. Reapproval remains denied after a blocked transition
  until a separately designed new-generation owner ceremony exists.
- **Immutable transition guard:** Normal SQL UPDATEs cannot clear or
  change a prepared denial or rewind its sealed receipt digest.

The test-only `oauth-pre-deny-intent-coordinator.mjs` now optionally
uses two provider-held restricted callbacks, `prepareIndependentFence`
and `sealIndependentFence`. When the disposable witness flag is set,
both are mandatory and independent. PREPARE is called **before** any
archive PUT; SEAL is called after archive readback and fresh owner
proof but **before** the monotonic signer publication. Missing/lost
acknowledgments fail closed and never automatically clear the witness.

## Test evidence and limitations

The hosted independent-witness job provisions two real PG18 clusters
with distinct physical system identifiers, applies v1..v7 migrations,
creates separate restricted logins and verifies role isolation,
exact SQL-vs-JavaScript receipt bytes, unsafe migration refusal,
preparer idempotency, no new post-PREPARE signed-write reservation,
no active witness read after PREPARE, denied block before exact
retained-receipt seal, unresolved PDS commits preventing revocation,
and deterministic ordered concurrency when a signed writer holds a
shared witness row lock before a denial begins. The older independent
witness and S3 source/test suites also run.

**The S3 archive in this test is a disposable memory-based test double.**
Its COMPLIANCE mode, version history, retention/custody, operator
independence and monotonic latest-head signer have not been certified
against a real provider. The test's positive commit settlement is a
controlled fixture exercising the previously tested restricted SQL
reconciler, not evidence of a hosted independent signer/CAR/outbox
recovery ceremony.

## What still prevents production completion

1. A **separately administered** and demonstrably nonrewindable
   latest-head signer and independently versioned, COMPLIANCE-retained
   S3-compatible object store with 400-day custody according to the
   release profile; real negative delete/overwrite, conditional PUT,
   version enumeration, retention shortening and signer-PITR tests.
2. Actual native ActivityPods owner/WebID + SAI readback and current
   browser-session credential-epoch proof, including password change,
   logout, revocation, app uninstall, reapproval and orphaned
   prepared-denial recovery.
3. Wire every OAuth code/access/refresh, introspection/DPoP,
   browser grant and signed-PDS entry point to the **current external
   nonrewindable denial head**, not just a locally rewindable witness
   SQL row. The active signed-head read is NOT an unconditional
   permit: the real signed writer must reserve its durable independent
   intent and hold the canonical PG consent lock during COMMIT.
4. Integrate the preparer/attestor with real independently administered
   credentials and their exact WORM receipt readback; enforce
   idempotent manual recovery of unknown commits without guessing.
5. Reconcile **physical** canonical PG, witness PG, Redis, Jena and
   PDS/CAR/outbox snapshots against the independent retained head
   after partitions and PITR. Rotate previously tracked credentials,
   complete full owner lifecycle, hosted positive signup, performance,
   security review and independent operator signoff.

Passing this v7 SQL proof is a substantial, tangible writer-ordering
increment. It is **not** permission to reopen production signup or
PDS OAuth issuance.
