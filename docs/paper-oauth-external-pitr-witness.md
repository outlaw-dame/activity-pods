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

## v3 immutable proposed signed-head binding (NONACTIVATED)

The v2 witness intent captured the expected **prior** signed head, but not
the immutable **proposed** commit CID. That made a settlement claim for an
unrelated signed commit too easy to confuse with the pending operation.
The additive v3 migration `paper-oauth-external-restore-witness-v3-bound-commit-intents.sql`
requires BOTH distinct, canonical CIDv1 DAG-CBOR commit CIDs in the
separately maintained witness record. It fails closed when any existing
intent would require an unsafe guess/backfill, removes the unsafe
six-parameter writer reservation entry point, and replaces it with an
exact seven-parameter reservation. The dedicated writer cannot supply
an unchanged proposed head or bypass the sealed grant epoch. A separate
reconciler can settle `committed` only for that recorded proposed CID;
it cannot substitute a different, otherwise correctly formatted CID.
Both expected/proposed CIDs and the hashed grant become readable only
through the restricted intent read function for independent proof.

The real reference-MST writer already calculates its prospective
signature/CID *before* reserving the external witness intent. The v3
disposable proof now stores that precise CID in the witness and confirms
that primary-PG signed-mutation UUID, signed head and native outbox all
match; replay, stale grants, unsealed writes, changed-head and foreign
CID settlement reject. **Important:** Matching CIDs is necessary but
not sufficient to prove a commit occurred; the independent
signing-key/CAR/outbox reconciler, actual physical recovery barrier and
external WORM receipts are still required. Only candidate migrations
are supplied, not a production witness or a safe release.

## Independent positive-commit reconciler (NONACTIVATED candidate)

`pod-provider/backend/candidates/atproto-signed-repo-proof/independent-witness-commit-reconciler.mjs`
implements **positive commit reconciliation only**. It uses the v3
witness's read-only operation view, a dedicated primary-PostgreSQL
read-only LOGIN (no superuser, role escalation, or mutation privileges),
and a single REPEATABLE READ, READ ONLY **primary** PG transaction.
It verifies exactly one immutable signed mutation UUID with the
expected/proposed commit CIDs, owner WebID, managed DID, native
outbox and valid generation. It loads CID-addressed immutable DAG
blocks and the historical upstream `@atproto/repo` MST under bounded
read/byte limits; verifies the exact post path and before/after MST record digests,
checking that create/update/delete change precisely the claimed historical
path. It independently verifies **both previous and proposed v3 commit
signatures**, resolving the historic DID signing key separately at each
revision to accommodate legitimate signing-key rotation. A merely valid
CID or current-head signature does not authenticate the old MST state.
Keys must be obtained by a trusted resolver, never from a public client
supplied signing key. Only then does a **different** witness reconciler
role ask the independent database to settle that exact operation as
`committed`.

The disposable proof verifies that a forced rolled-back signed
transaction leaves the witness pending, a superuser primary database
connection cannot serve as independent evidence, the wrong signer
cannot settle the intent, and the correct restricted primary proof
settles exactly once. This module cannot decide `aborted`; a missing
row, a stale read replica or an unavailable host is never evidence of
a committed or aborted signed mutation.

This is **not** a production-ready recovery service. The signed
receipt and pending intent still require independent immutable
Object-Lock storage, historic DID PLC key authenticity and rotation
validation, a real primary-PG/WAL failover recovery barrier, and
strict runtime wiring/credential separation. The canonical primary
DB can itself be rewound; positive historical verification must be
backed by independently immutable high-water evidence before
production release.


## v4 reconciler privilege split — commit-only admission (NONACTIVATED)

`pod-provider/backend/sql/paper-oauth-external-restore-witness-v4-commit-only-reconciliation.sql`
removes the runtime witness reconciler's EXECUTE grant on the generic
`resolve_signed_write` function, which allowed both `committed` and
`aborted` settlement. Giving the same runtime worker the ability
to declare a write aborted would let a compromised positive-commit
verifier erase a pending witness barrier and cause a revocation ACK
before the primary signed transaction has definitely stopped.

The replacement `settle_verified_committed` is a narrowly authorized
SECURITY DEFINER wrapper that can ONLY settle `committed` and delegates
the exact proposed-CID check to v3. The old generic entry point is
revoked from all runtime roles and retained only for a privileged
migration operator; its use in disposable tests is an explicitly
separate root recovery fixture **after** independently verifying
the primary transaction did roll back.

No production runtime or auto-recovery service is granted an abort
capability. Aborts that cannot yet be proven against a completed
independent primary WAL/recovery barrier **remain pending indefinitely
and prevent successful witness revocation**. A future isolated,
independently audited abort attestor requires physical PITR failover
and WORM readback acceptance before a separate, carefully scoped
abort-only function/role may be contemplated. This v4 change is
a deliberate security/availability tradeoff rather than a claim of
completed self-healing.

## Immutable epoch receipt readback attestor — NONACTIVATED transport candidate

The additive `pod-provider/backend/candidates/oauth-worm-epoch-attestor.mjs`
proves an **exact-byte write-once/readback/seal order**, without creating a
second identity authority or adding a production service. The restricted
witness attestor first calls `get_unsealed_receipt` for the exact
(owner WebID, client ID, revision, random operation UUID). It never accepts
the proposed event SHA-256 from an HTTP client. The receipt body is bounded,
deterministic and contains only a version, SHA-256 subject pseudonym,
revision, operation UUID and witness event digest. Neither the owner WebID
nor OAuth client ID is written into the object key or body.

The private, explicitly `fixtureOnly` adapter must:
1. Prove the immutable-retention policy covers the **exact object key**
   using an independent policy reader before PUT. Ordinary object existence,
   S3 ETags and a PUT success response are not retention proof.
2. Attempt a create-only PUT with `If-None-Match: *`; a lost ACK is
   ambiguous and **not** evidence of absence. The storage writer may not
   mutate/delete old receipts or change retention rules.
3. Perform a separate, uncached, independently authenticated GET and
   constant-time compare the entire receipt body. A failed PUT is
   acceptable *only* when that GET independently proves the exact
   pre-existing immutable receipt. Missing, corrupt and inaccessible
   readback rejects without sealing.
4. Recheck lock coverage immediately before calling the **distinct**
   restricted witness `seal` SQL function. Failure, missing permissions,
   policy downgrade, stale/current-event mismatch or unavailable storage
   leave the epoch unsealed. There is no permissive fallback or
   post-failure optimistic retry.

Cloudflare R2 documents atomic `If-None-Match: *` on PutObject:
https://developers.cloudflare.com/r2/api/s3/conditional-operations/
and prefix/bucket retention locks:
https://developers.cloudflare.com/r2/buckets/bucket-locks/
Unlike self-enforcing S3 Object Lock compliance mode, R2 bucket-lock
rules **can be removed by a sufficiently privileged lock administrator**.
Therefore the lock-configuration principal must be independently
administered and unavailable to the provider, S3 writer, OAuth issuer,
reconciler, attestor, witness DB operator and database backup operator.
Independent policy readback cannot compensate for a shared
administrator who can subsequently remove the lock.

The two-PG18+Redis8.2 witness fixture now calls this actual attestor
candidate before its SQL `seal` transitions. The companion standard
Node test verifies absent/corrupt/partitioned independent readback,
failed policy checks before and after PUT, overwritten-object rejection,
lost PUT acknowledgement, malformed identities and denied SQL seals.
**Both exercises use an in-memory write-once map and a disposable
assumed-retention callback**, never a live locked R2/S3 resource.
Production wiring remains deliberately impossible unless the gate is
redesigned and independently security-reviewed.

**Unresolved P0:** external bucket creation and independently verified
IAM/lock configuration, physical **primary plus witness** PostgreSQL PITR
and WAL restore barriers, cross-object recovery high-water enumeration
and verified event/intent chain replay, immutable receipt coverage for
pending/resolved signed-write intents, hosted owner consent and full
cross-protocol positive account signup. The module does not and cannot
authorize `release=OPEN`.


## v5 immutable signed-write intent receipts — NONACTIVATED

The independent witness's v2–v4 SQL prevented a successful revocation while
a write was `pending`, but a signed write could be marked `committed`
before its **settlement receipt** existed in an independently immutable
archive. A witness PITR rollback could then erase either a pending intent
or its settlement evidence. This gate is **not production complete** without
external archive high-water restoration.

`paper-oauth-external-restore-witness-v5-immutable-signed-intent-receipts.sql`
fails closed on **any existing signed intent**; no automatic migration,
backfill or guessed outcome is permitted. For new intents, a BEFORE INSERT
trigger captures the exact sealed epoch event SHA-256 within the v3
reservation transaction. Two irreversible bits track independent receipt
sealing: `pending_receipt_sealed` and `resolution_receipt_sealed`.
The existing per-owner/client bounded admission cap also counts
**committed or aborted but unarchived** outcomes through an indexed
BEFORE INSERT check. Otherwise the original pending-only cap would
permit unlimited committed-but-unarchived rows and WAL growth.
The existing epoch-transition trigger is tightened so **either** an
unresolved intent **or a resolved intent lacking its archived outcome**
prevents a revocation ACK. The v4 positive-only runtime reconciler remains
unable to mark an intent `aborted`; settlement requires the pending
receipt already sealed.

The restricted attestor's `signed_intent_receipt(operation,phase)`
returns bounded deterministic line-framed UTF-8 bytes containing a
SHA-256 pseudonym of the length-framed owner/client tuple, operation UUID,
revision, hashed grant, captured epoch event digest, *both* exact signed
commit CIDs, receipt phase, and (on resolution) the exact committed CID or
privileged recovery result. Neither raw WebID, client URL, bearer grant,
nor private signing key enters the archived body. The `seal_signed_intent_receipt`
function accepts only SHA-256 of those **database-derived bytes**.
Sealing is monotonic and exact, with idempotent lost SQL ACK handling.
The writer role can query only
`verify_sealed_signed_intent(operation,owner,client,revision,old,new)`;
it cannot read raw rows, seal, settle or revoke.

**Required transaction sequence (not a deployed runtime):**

1. Privileged writer reserves the exact immutable operation ID and
   old/new signed heads in independent witness PG18. Unsealed `pending`
   blocks revocation immediately.
2. Independent archive writer conditionally creates object
   `paper/oauth-witness/signed-intents/v1/<UUID>/pending` with
   `If-None-Match: *`, after verifying independently controlled
   retention. Separate read-only credentials perform uncached exact
   readback, byte/digest comparison and retention revalidation. Only
   the *distinct* witness attestor may seal this pending receipt.
3. The trusted PDS signer must call the v5 sealed-intent verifier before
   BEGIN on canonical primary PG. The optional
   `verifyWitnessIntentSealed` callback is accepted by the disposable
   reference-MST writer **only** under the additional explicit
   `PAPER_OAUTH_WORM_INTENTS_DISPOSABLE=confirmed` test gate.
   Reservation alone is never sufficient when v5 is enabled.
4. Once a separately credentialed reconciler independently verifies the
   real signed commit, it calls **commit-only** settlement. The witness
   now has `state=committed` but still blocks revocation while
   `resolution_receipt_sealed=false`.
5. The independent archive attestor conditionally stores and reads back
   the immutable `.../<UUID>/resolved` receipt, including exact
   resolved outcome, before sealing. ONLY THEN can the witness revoker
   acknowledge a new epoch; the previously issued OAuth grant is
   invalidated on that ACK.
6. An unresolved or unprovable rollback remains **pending indefinitely**
   until a separate physical WAL recovery barrier and WORM-backed abort
   attestation have been proven. The ordinary runtime remains
   **incapable** of invoking generic `aborted` settlement.

The disposable proof
`proof-oauth-worm-signed-intents.mjs` uses two actual independent PG18
clusters, restricted role logins, and an in-process write-once Map.
The existing two-PG18+Redis8.2 witness proof also applies **v5**
and routes the *real signed reference-MST writer* through a separate
pending-archive attestor and exact sealed-intent SQL verifier **before
its primary signed transaction**, then routes independent positive
reconciliation through resolved-receipt sealing before revocation.
It covers unsafe historical-intent migration rejection, unsealed
reservation denial, forgery/privilege checks, exact receipt bytes,
SQL seal idempotency, committed-but-unarchived revocation denial,
and successful revocation only after separate resolved receipt seal.
**A Map and a fixture-only assumed-retention boolean are not WORM.**
Production still requires separately administered real Object Lock
storage with independently verified IAM/retention; a complete immutable
high-water enumeration, chain/fork and epoch+intent cross-check after
witness PITR; physical primary/witness PostgreSQL WAL recovery; safe
issuer/owner OAuth and real hosted cross-protocol account acceptance.
All releases remain **CLOSED**.


## v6 immutable epoch high-water on OAuth admission — NONACTIVATED

A restored primary PostgreSQL **and** an independently restored witness
PostgreSQL can both agree on an old, cryptographically valid consent grant,
even when Redis and JWTs are similarly restored. v5's receipt state machine
prevents missing archive writes in an intact witness, but does not itself
detect **a witness database rollback**. The operator must not infer
anti-PITR protection from separate PostgreSQL instances alone.

The additive independent witness migration
`paper-oauth-external-restore-witness-v6-immutable-highwater-read.sql`
adds a narrowly granted read-only `active_checkpoint` function. It returns
only the exact sealed active epoch's revision, SHA-256 event digest and
operation UUID, and only when current and historical event rows match on
owner/client, epoch, grant hash, state, operation and digest. The restricted
`paper_oauth_witness_reader` receives no table DML or attestor privileges.

The disposable `createDisposableOauthWitnessReader` can enable a **separate**
high-water admission path only with the additional explicit
`PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE=confirmed` test gate and a private,
independently credentialed `readImmutableHeadReceipt` callback. That
callback must select the **highest independently retained epoch** from a
separately administered immutable archive, verify Object Lock policy and
exact readback, and return the raw bounded immutable epoch receipt bytes.
The OAuth request does not select the archive object, digest, revision or
key; a boolean from the client is not authoritative.

Each fresh admission verifies the restricted current witness checkpoint,
reads and validates the immutable high-water body (including the exact
owner/client domain-separated subject SHA, operation UUID and event digest),
then reads the restricted checkpoint **again**. A restore, rotation,
missing/corrupt archive object, stale read, mismatched high-water, foreign
subject, concurrent witness generation change or archive partition fails
closed. No positive authorization cache or automatic network retry exists.

The expanded two-physical-PG18+Redis8.2 proof starts with a genuinely
sealed current grant, then acknowledges a newer revocation and stores its
epoch in an **in-memory** write-once archive substitute. It deliberately
rewinds the primary PostgreSQL OAuth row, Redis grant and independent
witness PostgreSQL current row to their old active revision. Ordinary
SQL-only authorization and a signed JWT introspection would accept that
snapshot. The external-high-water path rejects it, including through
the real signed JWT introspection service; it also rejects absent and
foreign-owner archive receipts. The restricted witness row is restored to
its newer blocked state before the rest of the test continues.

**Critical production gap:** The test performs privileged **logical-row**
rewinds, NOT physical `pg_basebackup`/`restore_command`/WAL replay/PITR
of both clusters. The test's Map has no independent administrator,
retention guarantees or authoritative proof of complete highest-object
enumeration. A real deployment must independently prove that the
high-water lookup can never itself rewind or omit later retained receipts,
including after the archive reader or database restarts. Signed-write
pending/resolved receipt chain replay and WAL-based aborted-transaction
evidence remain prerequisites. This nonactivated candidate cannot open
production signup; `release=CLOSED` and federation P0 #186 stay in force.


## S3 Object Lock COMPLIANCE archive transport — NONACTIVATED integration candidate

`pod-provider/backend/candidates/oauth-s3-compliance-archive.mjs` is a
concrete AWS S3 API **COMPLIANCE** mode archival transport, not another
Map-based archive. It accepts independently constructed S3 write/read
clients and the upstream `@aws-sdk/client-s3` command constructors; it
holds no credentials, provider token or storage administrative role.
Nothing in a production Moleculer service imports it. The factory
requires the explicit test-only gate until independent operational
approval and final admission wiring.

For an **exact witness-generated epoch receipt or v5 pending/resolved
signed-intent receipt** the transport validates a strict bounded,
privacy-pseudonymous wire format, then:

1. Independently query `GetBucketVersioning` and
   `GetObjectLockConfiguration` with the **read principal**. Both S3
   versioning and Object Lock must be enabled. The bucket *default*
   retention must be **COMPLIANCE**, never GOVERNANCE, with at least
   400 days configured in the current disposable proof.
2. Attempt `PutObject` with `If-None-Match: *`, MD5 and SHA-256
   checksums. It does **not** create an overwrite path, change
   retention or delete a previous version. A lost PUT acknowledgment
   or existing-key conflict remains **uncertain**, never a positive
   attestation by itself.
3. Independently `HeadObject` for a current, non-null S3
   `VersionId`; `GetObjectRetention` for **that specific version**
   must report `COMPLIANCE` with the minimum retained-until date.
   Perform a separately authenticated version-targeted `GetObject`,
   bounded stream read and constant-time byte comparison. The S3
   `ETag` is *never* accepted as a cryptographic digest.
4. Recheck the **current** S3 version and the bucket lock
   configuration after readback. A delete marker, replacement,
   permissions failure, expired retention, wrong version, oversized
   stream, malformed receipt or unavailable storage fails closed.

This transport is intended for the isolated attestor that reads the
expected bytes from witness SQL, not from user requests. The independent
operator must still audit and enforce all of the following **before
production use**: dedicated S3 COMPLIANCE account under independently
controlled lifecycle; no writer/reader/admin credential reuse; separate
read-only verifier with `GetObjectVersion`/retention/lock permissions;
write-only conditional PUT policy, with no `DeleteObject`,
`DeleteObjectVersion`, `PutObjectRetention`, `BypassGovernanceRetention`,
`PutBucketObjectLockConfiguration`, versioning/lifecycle policy or
account-deletion authority on runtime identities; immutable audit of
configuration and credentials; backup plus token lifetime shorter than
retention; globally fenced restore epoch. An SDK client's JavaScript
identity inequality alone **does not prove principal isolation**.

The matching CI
`.github/workflows/paper-oauth-s3-compliance-archive.yml`
exercises negative paths and both deterministic fake transport and
**actual pinned Apache-2.0 AWS S3 SDK command objects**. This is
still NOT a live S3 server, not a real COMPLIANCE retained object,
not a verified deployment, and not independent security certification.
The object archive cannot by itself prove that a PG transaction can no
longer commit, nor can it solve historical high-water completeness
without complete independently retained enumeration and a WAL
failover barrier. An independently managed production bucket and
positive hosted signup are still required.

Normative sources:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/s3/command/GetObjectRetentionCommand/

## S3 immutable version history high-water — NONACTIVATED reader candidate

The S3 COMPLIANCE transport also implements
`readLatestEpoch({owner,clientId})` as a private archive-only helper for
the existing `oauth-external-witness-reader.js`
`readImmutableHeadReceipt` callback. This is not a production
connection and cannot be used outside the explicit disposable CI gate.

**Important S3 Object Lock property:** COMPLIANCE protects a *specific
version* against deletion; the ordinary `DeleteObject` operation can
still create a **delete marker** that obscures that locked version from
`ListObjectsV2` or unversioned `GET`. Therefore no OAuth high-water
algorithm may simply list visible current objects or trust an ETag.
Source:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html
https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html

The helper derives the exact SHA-256 owner/client pseudonym used by the
epoch receipt writer, queries the **entire historical version list**
with `ListObjectVersions`, including `DeleteMarkers`, and checks
monotonic zero-padded revisions from **1** with no missing sequence,
unexpected keys, duplicate/multiple versions, masked objects, false
`IsLatest`, or skipped pages. All operations are bounded (max 4096
receipts, at most eight 1000-item pages); exceeding the cap **denies**
authorization, never guessing a latest head. It then verifies the
**specific latest version**, COMPLIANCE retain-until-date with a
configurable minimum **remaining** lifetime (separate from the bucket's
initial ≥400-day retention), exact bounded canonical bytes, current
HEAD version and second independent bucket-lock configuration check.

An authenticated caller must pass the resulting **uncached bytes**
to the witness reader's SQL `active_checkpoint` comparison
**before AND after** S3 IO; read/list failure or any changed PG head
must fail closed. The archive transport alone does not know whether
the current PG primary has been physically rewound, and this helper
does **not** itself authorize any token or signed PDS write. An S3
reader missing `s3:ListBucketVersions` or
`s3:GetObjectVersion` / `s3:GetObjectRetention` must fail closed.
Document and audit actual IAM policies, not just JavaScript client
instance inequality.

**Still P0:** A malicious/incorrectly configured storage intermediary
that silently omits a **newer** version can return an apparently
contiguous **older** history. The disposable test explicitly models
that limitation. Independent bucket-account ownership, complete
version-list IAM, strong-consistency operational verification, an
independent monotonic anti-rollback/incarnation anchor, cross-object
signed-write intent receipt chain replay and real dual PostgreSQL
WAL/PITR recovery remain requirements. Listing every version on each
JWT check is also an O(n) cost that must be resolved before high-scale
release without caching positive authorization across restore
boundaries. The provider currently does **not** load this candidate
and `release=CLOSED` remains mandatory.


## Two-PG18 / Redis high-water proof via actual S3 API verifier — NONACTIVATED

The disposable `proof-oauth-external-witness.mjs` previously used
an ad hoc in-memory sort for the `readImmutableHeadReceipt` callback.
It now invokes the actual `createS3ComplianceReceiptArchive`
`readLatestEpoch` code against a **test-only in-memory S3 command
transport**, and passes those exact retained bytes into the
restricted `createDisposableOauthWitnessReader` PG18 v6
`active_checkpoint` before/after authorization checks. The mocked
reader exposes versioning, Object Lock COMPLIANCE, per-version
retention, version-targeted GET, current HEAD and full
`ListObjectVersions` including delete-marker enumeration. The
high-water client's fake writer throws on any attempted write.

The two physically isolated PostgreSQL 18 containers plus Redis 8.2
test therefore prove the **composed** candidate path: a valid
signed JWT with restored primary PG + Redis + witness PG rows is
rejected because its independently retained, later epoch is observed
by the S3 version-history verifier. A delete marker on an existing
retained object also denies OAuth admission. No successful token
admission result is cached across an independent archive check.

This does not replace an actual S3 COMPLIANCE service,
independently audited IAM/account custody, physical witness PITR
reconciliation and WAL abort barrier, nor the unresolved signed-intent
receipt history requirements. The storage transport remains a test
substitute, no production credential/runtime path has been wired,
and `release=CLOSED` remains enforced.


## Primary-only independent witness admission (NONACTIVATED)

The restricted OAuth witness reader rejects PostgreSQL hot-standby connections
using `NOT pg_catalog.pg_is_in_recovery()` in **every** per-request role
admission query. A lagging replica can hold consistent but stale witness
rows, including an authorization that the primary has revoked. A missing
or false primary predicate denies the authorization before any grant lookup.
The two physically separate PG18 / Redis fixture checks a real primary
and fault-injects a valid-looking standby admission response. This rule
is **not** a failover/PITR activation barrier: a newly promoted but rewound
primary can return true and still must be fenced by independently immutable
high-water receipts and verified WAL recovery. No production activation;
`release=CLOSED`.


## Owner account liveness at OAuth authorization — runtime hardening

The existing OAuth `/oauth/authorize` handler authenticates an
HTTP bearer or signed browser cookie before issuing an authorization
code. A cryptographically valid credential alone does not establish
that the associated account has not subsequently been deleted.

The SemApps upstream `auth.account.findByWebId` action queries the
account record directly; unlike the generic `auth.account.find`
action, it does **not** filter `deletedAt` tombstones. Paper therefore
must query the authoritative account service on **every OAuth
approval attempt** and compare the exact canonical HTTPS WebID,
rejecting a missing, unavailable, mismatched or tombstoned account.
A signed bearer or browser cookie cannot bypass this check. A failure
to look up the account is **deny**, not permission to proceed with a
cached owner identity.

`/oauth/session/login` now uses the exact account returned by the
upstream password verification action, rather than making a separate
`findByUsername` query afterward. This removes a second lookup
race, also preserving SemApps' documented ability to verify usernames
or email addresses. A tombstoned or malformed verified account is
refused before a session cookie is issued. The existing
`proof-oauth-owner-bearer-signature.cjs` tests signed RSA and HMAC
cookies, deleted/mismatched/absent account records, credential
verification outages, email logins and invalid owner identities.

**Still required for production:** live authoritative account
suspension/disable policy and atomic ownership/consent proof, strong
browser session invalidation on logout/password change, externally
retained non-rewindable independent witness, real post-enrollment
owner grant/revoke, hosted positive cross-protocol signup and
independent security review. At the #282 baseline, the browser session remained stateless
HMAC with finite TTL; that change did not provide server-side cookie
revocation or fully released OAuth grant authority. Staging signup
must stay CLOSED.

## Cross-replica browser logout and consent-write ordering — nonactivated gate

The previous HMAC-only session was retained after logout in any copied
browser cookie until its expiration. The next candidate replaces cookie-only
authority with a 32-byte CSPRNG session id, server-signed `iat/exp/WebID/id`
cookie and a **Redis 8.2 live allowlist**. The registry persists only SHA-256
session-id and WebID digests with bounded expiry; a session must receive an
acknowledged `SET ... NX EX` before login sends a cookie. Existing HMAC
cookies without the id/issued-at fields are intentionally rejected.
`POST /oauth/authorize` performs a fresh registry read and the existing
non-tombstoned account lookup, with no positive admission cache. The
`GET /oauth/authorize` browser UI does not advertise an already revoked
cookie as signed in. Logout atomically compares the exact owner digest and
deletes the session id, requiring a successful Redis result before sending
the cookie-expiration response. Inaccessible Redis fails closed; an
ambiguous delete/write acknowledgement never claims successful revocation.

**Critical same-store race fix:** For browser approval, `oauth-api` passes the
validated cookie session id through `oauth-authorization.authorize` to
`oauth-consent.upsert`. The consent service evaluates live session and
owner digest **in the same Redis Lua operation** that writes the new grant.
It therefore cannot issue a new grant *after* the same Redis has processed
logout, even if the HTTP request previously verified the session before the
logout. Provider-verified signed bearer flows retain their separate owner
signature and live-account checks.

Dedicated disposable `proof-oauth-browser-session-redis.js` uses two
independent Redis clients/provider contexts to verify cross-replica
revocation, wrong-owner denial, legacy-cookie invalidation, failure to issue
a cookie without create acknowledgement, outage denial, and post-logout
consent-upsert refusal without mutating the earlier grant. No live
production-session secrets or Redis data are read or logged.

**Not a production-restoration certificate:** Redis backup restoration
can restore an older live session key or consent. This candidate does NOT
seal each browser-session issuance/revocation against the independent
witness or guarantee its survival under Redis/PG PITR. Password changes
and credential reset still require a canonical revocation-generation
integration for all existing sessions; no general revoke-all service
or account-deletion/disable transaction fencing is asserted.
Authenticated owner post-enrollment consent, fully integrated
production PG/SAI/PDS admission, independent WORM with WAL failover proof,
hosted positive browser/Solid/ActivityPub/ATProto signup and independent
security review remain P0. Keep `release=CLOSED`.

## Password-verifier-bound OAuth browser sessions — nonactivated hardening

The SemApps account service has **three separate credential-mutation**
actions: `auth.account.setPassword`, `setNewPassword`, and
`updateAccountSettings`. They all replace the account's
`hashedPassword`, while an event hook for a global revocation
generation is not guaranteed. Adding a callback to just one endpoint
would miss other password-reset paths and crash windows.

Paper's browser-session candidate therefore requires a **current
credential-version proof on each authorization**. At successful
username/email + password login, the provider HMACs a domain-separated
canonical [WebID, stored password verifier] pair using its existing
private OAuth session signing secret. Only the resulting fixed-length
MAC is included in the signed HttpOnly browser cookie; no raw bcrypt
verifier or password is copied to browser storage. The cookie still
requires the live Redis session registry.

At each browser POST approval, the account record is freshly resolved
and its current verifier recomputed and compared in constant time.
A password change via any of the SemApps account mutation actions
alters the underlying verifier and therefore refuses an older signed
cookie, even if its Redis session key has not expired. The GET
authorization UI likewise does not display this stale browser session
as active. A missing, malformed or passwordless verifier fails closed
for password-authenticated browser sessions, and older cookies lacking
this proof are intentionally invalidated on deployment.

Tests cover current password/session admission, changed-verifier
denial despite a live Redis key, rejection of missing verifier,
malformed legacy cookies, cross-replica logout, and the same-Redis
atomic consent upsert. They use fabricated verifier strings, never
live credentials.

**Important limitations:** This is an effective password-change
admission fence only while the current authoritative account record
remains non-rewound. A simultaneous Jena account/password change and
Redis consent write is not one cross-store PG transaction. Restoring
the former hashedPassword plus Redis/session snapshot could revive
pre-revocation admission without the independent WORM epoch. Existing
SemApps RS256 bearer tokens do not contain this new verifier proof and
can still authorize according to their separate max-one-hour age
policy; password-change revocation of *all* bearer/refresh/session
credentials requires provider-level canonical account/epoch authority.
The production fuse remains `release=CLOSED` until those barriers,
hosted owner OAuth and positive Solid/SAI/PDS/AP signup, and independent
security review have genuine acceptance evidence.

## Post-enrollment owner grant revocation — staged live-session CAS

The prior OAuth flow could record owner approval during authorization but
did not expose a session-authenticated *post-enrollment* owner grant
inspection/revoke endpoint. Ordinary `POST /oauth/revoke` is a refresh-family
token revocation operation, **not** owner consent revocation.

A dedicated browser-owner-only API adds:

- `GET /oauth/owner/grant?client_id=<canonical HTTPS OAuth client-id>`:
  requires a current signed, Redis-registered, password-verifier-bound
  browser session and live non-tombstoned account lookup. Reports
  `consented=false` if that owner has no active grant. For a current grant
  it returns that exact opaque grant generation, scope and an independently
  random one-use revocation challenge and CSRF token. It never lists
  another owner's grants or exposes a raw password verifier.
- `POST /oauth/owner/grant/revoke`: **same-origin HTTPS**
  `Origin`, `Content-Type: application/json`, and same-origin
  `Sec-Fetch-Site` when supplied; signed browser session mandatory,
  historical RS256 bearer fallback is rejected. The JSON body requires
  `client_id`, `grant_id`, `challenge_id`, `csrf_token`, all
  returned by the preceding GET. The challenge is consumed via Redis
  `GETDEL` exactly once and binds WebID/session/client/grant, stable
  user-agent/IP fingerprint and CSRF hash. Malformed, expired and reused
  challenges are denied without a grant mutation.

The actual consent change is one **Redis Lua** operation that verifies
the owner session key and SHA-256 owner digest, checks the existing
consent record's canonical owner/client and **exact grantId**, and marks
that precise generation revoked while preserving the original TTL.
A lost Redis ACK is not retried. If a later owner reapproval creates a
new consent generation after GET and before POST, revocation returns
HTTP `409 consent_changed` and **cannot overwrite the new grant**.
The revoke and concurrent logout serialize on the same Redis instance.
No unbounded Redis key scans, O(N) token-family walks or positive caches
are introduced.

The existing real Redis 8.2 two-provider proof exercises enrollment
session, live owner grant GET/POST, stale-generation conflict, repeated
CSRF, bad Origin and Fetch-Site, bearer rejection, changed-password
session rejection, unrelated client absence, subsequent grant readback,
and cross-provider logout. The two OAuth endpoints remain available for
staging under the **closed signup fuse**, and are not evidence of
production positive hosted signup.

**Critical boundary:** `oauth-consent.revokeOwnerGeneration` marks the
Redis grant. It does not yet issue an independently retained immutable
PostgreSQL/Jena/Solid/SAI/PDS revocation epoch. It cannot promise denial
after simultaneous Redis/PG/Jena rollback; the per-token PG/witness
candidate remains strictly `NODE_ENV=test` and nonactivated.
Any real Paper permission-management UI must distinguish application
OAuth/ATProto consent from independently delegated Solid storage grants
until cross-store release criteria are met. Keep `release=CLOSED`.

## Public OAuth Authorization Interface rejects old SemApps bearer owner credentials

The current upstream SemApps `auth.jwt.generateServerSignedToken` path
issues RS256 user bearer JWTs that carry an `iat` timestamp but **no
password-verifier version or canonical account revocation epoch**. The
former Paper public `POST /oauth/authorize` path accepted a valid
server-signed token issued within the past hour as proof of owner
consent, even if its owner had changed their password after issuance.
Checking the current account's WebID and deleted tombstone did not
close this password-change replay.

Paper's public OAuth consent approval now calls
`requireBrowserOwnerSession` rather than the broader
`requireUserWebId`. It requires the current HMAC-signed,
Redis-registered, password-verifier-bound browser cookie, plus a fresh
live account lookup. Any `Authorization` header (including a
correctly verified old RS256 bearer) is **rejected** even if the
request also includes a valid cookie; it never falls back to the
cookie. The existing same-Redis Lua grant-upsert guard still checks
the exact live browser session atomically against logout. The
existing one-use PAR challenge and CSRF checks are unchanged.

This follows the AT Protocol OAuth Authorization Interface's required
user-facing authentication and grant approval model; old API bearer
credentials are not a substitute for a current user authorization
session. See https://atproto.com/specs/oauth .

The internal `POST /api/internal/oauth/authorize` remains a separate
admin-authenticated, **production-disabled** compatibility fallback.
This change does not claim to revoke SemApps-issued bearer tokens from
other SemApps/Solid endpoints; those need a canonical owner credential
epoch and issuer/validator integration. Nor does it replace external
WORM/WAL/PITR or signed PDS/SAI cross-store consent transactions.
The release fuse stays `CLOSED` until hosted positive end-to-end
acceptance and independent security review.

Tests create real RS256 signatures to distinguish correct but stale
bearer from forged/unsigned bearer; assert denial of public consent
even with a valid old token and HMAC cookie, changed-password cookie
denial, and success of a valid browser owner approval carrying its
exact Redis session ID to the consent grant authorization action.

## Browser POST same-origin enforcement — provider login/consent/logout

The provider-generated `/oauth/authorize` HTML form posts login
credentials and consent decisions to the issuer's **own** origin.
Until this gate, the request handlers relied on password verification,
one-use CSRF and SameSite cookies but did not check the browser's
`Origin` before minting a new signed session. A third-party form
could attempt login CSRF (placing a victim's browser into an
attacker-controlled account context).

The browser mutators now share one `requireBrowserPostOrigin`
policy: exact canonical HTTPS issuer origin; reject missing, null
or conflicting `Origin` headers; reject supplied cross-site
`Sec-Fetch-Site` and conflicting metadata; reject cross-origin
credential/approval requests **before account password verification
or any Redis session/grant mutations**. JSON and
`application/x-www-form-urlencoded` submissions are accepted for
the provider's legitimate form UI. Owner grant revoke remains
JSON-only. Empty-body, same-origin logout is allowed without a
`Content-Type` header, but not without matching `Origin`.

The policy applies to `POST /oauth/session/login`,
`POST /oauth/session/logout`, `POST /oauth/authorize` and
`POST /oauth/owner/grant/revoke`. It deliberately does **not**
change protocol-level cross-origin clients' `/oauth/par`,
`/oauth/token`, `/oauth/revoke`, or the separately authenticated
production-disabled internal authorization fallback. No wildcard
CORS or new trusted client origins are introduced; the existing
OAuth HTML form is hosted at the issuer. A future separately hosted
UI must use a deliberate, reviewed first-party origin design rather
than silently widening this issuer gate.

Live Redis8.2 and RS256 cryptographic proofs cover malicious
Origin, absent Origin, conflicting case headers, cross-site
Fetch-Metadata, invalid `Content-Type`, no password verification
or session mutation on denial, positive form/JSON owner flows,
and empty-body logout. This boundary does not independently
attest WORM receipts, canonical PG/Jena/SAI/PDS epoch ordering,
or positive hosted signup. The release remains `CLOSED`.
