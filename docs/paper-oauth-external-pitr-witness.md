# Paper OAuth/PDS external restore witness — P0, **NONACTIVATED**

Last checkpoint: 2026-11-21. Owner: ActivityPods account authority; cross-repo
staging release remains **CLOSED**. Primary issue:
https://github.com/outlaw-dame/mastopod-federation-architecture/issues/186

## Threat model and assumptions

Restoring an old Redis RDB/AOF or canonical PostgreSQL PITR snapshot can
resurrect *cryptographically valid*, unexpired OAuth access/refresh/session
credentials and account grant rows that had been revoked after the backup.
A PostgreSQL CAS and revoker row lock protect concurrent live traffic, but
cannot protect a database after its own backup is rewound. A separate
failure-domain authority must reject older epochs on every credential
admission, including all signed PDS write commits.

The witness must not share the primary PG database cluster, disks,
snapshot catalog, restore credentials, service account, lifecycle, or
unrestricted administrator with the original. Its supported deployment
requires independent durable object storage with immutable receipts
(such as separately administered Cloudflare R2 bucket locks or an
S3/MinIO Object Lock COMPLIANCE bucket). **A second database alone is NOT
proof of non-rewindability.** A witness restore without reconciliation
against the independent immutable audit receipts must serve **503 / deny**
rather than accepting an older authorization state.

Official reference: https://developers.cloudflare.com/r2/buckets/bucket-locks/
— R2 bucket locks prevent deletion and overwriting while retained, but
users with bucket-lock configuration authority can remove rules.
Therefore isolate the lock-control account and deny it to the provider,
writer, OAuth issuer/revoker, runtime attestor, and backup/restore roles.
https://minio.community/community/minio-object-store/administration/object-management/object-retention.html
describes S3 Object Lock COMPLIANCE mode for self-hosted alternatives.

## Candidate implementation and exact failure order

`pod-provider/backend/sql/paper-oauth-external-restore-witness-v1.sql`
belongs exclusively on an **independent PostgreSQL 18 witness cluster**.
Each (owner WebID, client ID) has a monotonic, contiguous revision and
a linked SHA-256 event history. No runtime principal has raw table
SELECT/INSERT/UPDATE/DELETE privileges. Dedicated NOLOGIN roles for
issuer, revoker, WORM attestor and reader receive only respective
SECURITY DEFINER function EXECUTE privileges.

The safe transition protocol is:

1. A separately authenticated owner approval (or owner revocation)
   passes the real canonical PostgreSQL signup/session journal. Verify
   exact owner, client, scope and fresh signed native SAI consent, with
   explicit intent. General post-signup session approval still needs
   a distinct owner-authenticated gate; the 10-minute signup token must
   not become a permanent authorization mechanism.
2. Send a unique operation UUID and the **hashed grant ID** to the
   independent witness. Its serializable-per-key CAS advances revision,
   records the chained event and resets `sealed=false`. An acknowledged
   revocation denies immediately, even if the canonical PG mutation
   has not completed. A newly issued grant is unusable while unsealed.
3. Write the event receipt to an append-only immutable R2/S3 key
   scoped by a SHA-256 owner/client pseudonym and revision, with
   `If-None-Match: *`; use bucket-level retention locks. After
   ambiguous ACK, perform an independent GET to verify exact bytes
   and SHA-256. The issuer must never be permitted to tamper with
   protected objects, relax bucket locks, or self-attest receipts.
4. Only a separately privileged witness attestor, after immutable
   readback, calls `seal(owner,client,revision,operation,eventSha)`.
   If object PUT/GET or attestation is unreachable, retain the
   unsealed state and **deny all** authorizations.
5. Project that exact generation into canonical PostgreSQL (same
   managed WebID/SAI and owner consent) and Redis (ephemeral grant/family).
   The issuing coordinator must consider ambiguous cross-store ACK
   a reconciliation requirement, never a reason for blind replay.
6. Every code issue/redeem, signed JWT introspection, refresh
   rotation/issue/introspection, old browser cookie/session admission
   and signed-PDS transaction calls **all required** current authorities:
   Redis grant, primary PG canonical SAI/OAuth, independent witness,
   current DID/signing key and current owner session. Stale/missing/
   restored witnesses, PG read replicas, ambiguous replies, and
   cancelled requests deny. No positive authorization cache across
   replica changes or restore boundaries.

The SQL witness supports steps 2, 4, and read verification as a
**nonactivated candidate**; no production external Object Lock bucket,
readback attestor, restricted runtime LOGIN, or owner-session wiring is
deployed by this migration.

## Recovery and operations

A witness rollback is as dangerous as canonical PG rollback. The
recovery service must enumerate the immutable receipt chain and validate
every revision, prior hash, unique operation, owner/client digest and
highest sealed revision; reject gaps, forked high-water or nonexistent
receipts. After a witness restore, block token admission and signed
PDS writes until independent readback agrees. A restored primary PG
behind that high-water remains blocked until an authenticated owner
explicitly reauthorizes and a reconciler advances PG to a witnessed
state. Do not automatically change a blocked witness to active.

Use separate TLS/mTLS private network identities for primary vs witness,
read-only credentials for admission, different issuer/revoker and WORM
attestor identities, complete key rotation, isolated storage accounts
and strict IAM on bucket lock configuration. Monitoring must include
witness availability, PG/witness revision divergence, WORM seal lag,
ambiguous cross-store acknowledgements, backup-age floor and restore
readiness; no uncontrolled blind retry.

For retention, the immutable receipt lifetime must exceed the maximum
age of recoverable backups **and** the maximum lifetime of any legacy
refresh/session credentials plus recovery/replication grace. Minimize
personal data: receipt objects should contain pseudonymous hashes and
operation digests only. If the external retention policy must eventually
expire, an independently verifiable global recovery incarnation fence
is also required so an ancient backup cannot bypass deleted tombstones.

## Verified in disposable CI vs outstanding production acceptance

`pod-provider/backend/scripts/proof-oauth-external-witness.mjs` and
`.github/workflows/paper-oauth-external-restore-witness.yml` exercise
two **physically separate PG18 containers** and Redis 8.2, distinct
privileged-role logins, PG row rollback of canonical OAuth, native
Redis binary DUMP/RESTORE, independent witness high-water and sealed
vs unsealed authorization. The test WORM transport is an explicit
in-memory write-once **test substitute**, NOT real Cloudflare R2 or
S3 Object Lock; the PG rollback is a deliberate logical-row restore,
NOT a full WAL/PITR or failover.

The following are **still blocking P0** and cannot be satisfied by a
green SQL-only test: real externally locked WORM bucket and actual
PUT/readback attestor, witness PostgreSQL backup/PITR restore catch-up
with chain verification, hosted mixed failure domains, all real OAuth
and browser session credential admissions, transactionally locked
signed-PDS writer, actual current DID/PLC key custody/rotation, positive
new account WebID/Solid/ActivityPub/PDS signed write and remote
readback through the released provider stack. Record exact immutable
source SHAs, private-role grants, host restart outcomes and recovery
evidence before considering `release=OPEN`.

## Disposable read-side integration into the actual OAuth handlers

The optional, **test-only** `PAPER_OAUTH_WITNESS_DISPOSABLE=confirmed`
gate in `oauth-pg-epoch-policy.js` requires a fresh independent
`oauth-witness-epoch.verify` decision **in addition to** canonical
PG consent generation and Redis state on each real authorization
code issue/redeem, signed JWT issuance/introspection, refresh
issuance/rotation/introspection and protected PDS OAuth admission.
If the witness is absent, unreachable, unsealed or behind the
current PG generation, authorization rejects; there is no cached
positive result and no fallback to the primary account database.
Candidate is entirely disabled in production and refuses partial
test-only activation.

`pod-provider/backend/candidates/oauth-external-witness-reader.js`
connects to an **independently authenticated PG18 witness LOGIN**.
It revalidates the actual reader role, denies unexpected role
memberships and every table/issuer/revoker/attestor privilege,
checks an exact allowlisted HTTPS OAuth client ID, hashes the grant
ID, and executes only the current sealed witness verification
function. The ordinary provider, Pod, Jena user, PostgreSQL account
issuer and OAuth revoker do not receive this connection.

The two-physical-PG18 + Redis8.2 CI proof now invokes the real
`oauth-token.issueAccessToken` and actual signed-JWT
`introspectAccessToken`, checking that witness unavailability and
unsealed grants fail even with a valid primary PG revision and a
previously approved Redis grant. A simulated old primary PG row
and real Redis binary DUMP/RESTORE cannot reactivate an unexpired
signed JWT; new owner consent must use a fresh revision and be
independently sealed before signing succeeds.

**Remaining unimplemented:** A WORM-backed witness itself must
verify independent immutable high-water after *its own* PITR,
and PDS signing must coordinate witness revocation with its same-PG
commit lock so no write can linearize after an acknowledged
external witness revocation. A separate writer/witness lock lease
or comparably rigorous commit protocol must be verified under
crashes, partitions and backup restore. A passing two-PG SQL test
does not eliminate these blockers or permit production release.

## Durable signed-PDS writer admission barrier (v2, NONACTIVATED)

The independent witness migration
`pod-provider/backend/sql/paper-oauth-external-restore-witness-v2-writer-intents.sql`
introduces **durable pending signed-write intents**. Only the
independently privileged `paper_oauth_witness_writer` role may reserve
a unique UUID while the exact grant's sealed witness epoch is active.
It records the *prior signed repository head*; it cannot change OAuth
grants, acknowledge revocations or resolve its own uncertain writes.
A separate `paper_oauth_witness_reconciler` role alone may resolve
`committed` versus `aborted`, based on independently verified
PRIMARY PostgreSQL signed head, MST, native outbox, immutable blocks,
and (for abort) evidence of a completed crash/recovery barrier. No
client-supplied ACK, age-based release or Redis transient state counts.

A PostgreSQL trigger enforces that the revoker cannot transition the
witness generation to `blocked` while ANY intent remains pending.
Reservation and revocation race on the same PostgreSQL row lock; a
bounded per-owner/client advisory transaction lock serializes
reservation count/insert and caps pending writes. A crashed signer
leaves an unresolved intent that blocks a successful revoke ACK until
the independent reconciler has durable proof of the outcome.
This favors safety over availability: users may temporarily be
unable to complete revocation during a real database outage, which
must surface as an unavailable/pending revocation, NEVER as success.

**Required future integration:** the actual signed reference-MST
writer must reserve the witness intent before entering its primary
PostgreSQL commit transaction and must use the same immutable
operation UUID for the signed outbox/reconciliation journal. A
separately credentialed completion attestor must verify and
resolve after the primary commit; a lost/ambiguous COMMIT reply may
NEVER resolve as aborted from a transient missing-row read. The
witness may acknowledge a revoke only after that reconciliation.
Independent WORM writer-intent receipts and high-water recovery
are required: if witness PITR loses a pending intent, protection
degrades unless the external nonrewindable archive restores it.
Do not activate the v2 scheme before those guarantees are proven
in the hosted signer and after independent witness restoration.

The CI witness proof exercises two PostgreSQL18 clusters, restricted
writer vs reconciler vs revoker roles, duplicate/foreign epoch
reservations, denied unsealed and revoked reservations, blocked
revocation while an ambiguous write remains unresolved,
irreversible resolved intents and a new sealed epoch. Test program
validates database transactions and authority ordering, **not**
a production reference-MST signed PDS runtime or physical PITR.

## Reference-MST signed write correlation (NONACTIVATED integration candidate)

The reviewed `createReferenceMstWriter` accepts an optional
`reserveWitnessIntent` callback from the **trusted provider PDS
authorizer only**, not an HTTP or ActivityPub request. Whenever the
disposable witness flag is present, it requires all PG/Redis witness
fixture flags plus `lockCanonicalConsent` in the SAME primary PG
transaction. It signs a prospective reference-MST commit using the
pinned upstream `@atproto/repo`, then generates a cryptographically
random writer operation UUID, asks the separately credentialed
witness writer to reserve that operation against the sealed current
epoch **before** opening the primary repository transaction, and
records this exact UUID alongside the signed commit in the
`record_mutations` audit. That operation UUID and the native event
outbox are committed atomically with the signed head. No caller can
submit or reuse an operation ID through a public XRPC body.

The additional canonical-PG migration
`pod-provider/backend/candidates/atproto-signed-repo-proof/pg-witness-signed-head-correlation.sql`
adds a unique immutable operation UUID to the existing signed
mutation audit, **without** creating a new account identity. Missing
this migration fails the signed writer transaction closed; it must
not silently drop the witness correlation. The writer is forbidden
from settling a pending intent itself, even after it receives a
positive PostgreSQL COMMIT acknowledgement. A **different privileged
reconciler** must independently verify the durable signed commit,
immutable CAR/MST/record CID, native outbox and canonical PG
transaction status, and only then resolve the witness intent.
An uncertain COMMIT may never be guessed aborted. If PG and witness
become partitioned, no successful revoke ACK is possible while the
pending intent remains; this availability tradeoff is explicit.

The dedicated two-PostgreSQL18-cluster + Redis8.2 witness test now
also installs the separately pinned `@atproto/repo@0.11.0`, signs
a real reference-MST post with secp256k1, performs canonical PG
OAuth+native SAI consent lock in the primary transaction, verifies
the native signed-head/outbox and immutable witness audit UUID,
proves the **independent** witness blocks revoke ACK while that
commit is unresolved, then allows independently checked settlement.
It is a **disposable cryptographic integration proof**, not a
real hosted OAuth gateway or a deployed PDS. Real WORM receipts for
each witness epoch AND pending-intent mutation, independent witness
PITR/failover reconciliation, operational abort proof and remote
federation acceptance remain required for production.
