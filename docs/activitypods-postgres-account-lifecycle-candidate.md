# ActivityPods — PostgreSQL standard-account lifecycle candidate

**Status:** Experimental, non-activated, not authentication authority. November 11, 2026.

## Actual decision

PostgreSQL is a strong fit for the *transactional account control plane*: per-provider identity records, normalized username uniqueness, lifecycle generations, account suspension/deletion, operation idempotency and association indexes. Existing Group PostgreSQL proofs demonstrate the DB and bounded Moleculer integration can work, **not** that switching ActivityPods login from SemApps/Jena is safe.

The current canonical account authority is SemApps `AuthLocalService` backed by the settings RDF dataset. WebID documents, per-user Pods, WebACL, Solid-OIDC/SAI consent and protected AP/AT identity bindings remain in their current stores. No new credentials are stored in the candidate, no default service loads it, and it is impossible to activate through an environment variable. The candidate requires direct explicit `createCandidate({pool,fixtureOnly:true})` construction in a disposable test. It never sends ActivityPub, issues JWTs or checks Solid authorization.

## Candidate data model and guarantees

The isolated `paper_account_candidate` schema has a stable internal UUID account ID, provider-scoped unique lowercase ASCII username key, unique WebID association, state with valid transitions, positive generation and an operation ledger. **The UUID is an internal database key, not a third public protocol identity.** The account's unified identity binds exactly one WebID, the *same* ActivityPub actor URI, a unique `did:plc`, its ATProto handle and PDS URL, and proof that its repository was initialized. The binding is a single SQL transaction and cannot be partially populated. `ready` is impossible before the unified binding. The Solid-OIDC account/login and actual AP/AT credentials remain outside this isolated candidate. ATProto DID uniqueness and WebID = ActivityPub actor are enforced in SQL as well as the candidate adapter; real provisioning must validate the DID, PDS and repository in the existing provider before calling this candidate. Username uniqueness includes suspended/deleted entries deliberately: **name reuse is forbidden by default** until a separately reviewed retention and anti-impersonation policy permits it. Neither password hashes, sessions, device secrets nor OAuth grants appear in this schema. There is no copied user profile, social graph or private Pod content.

The proof adapter uses **one injected bounded node-postgres pool**, one borrowed connection per transaction, `SELECT ... FOR UPDATE` on the exact account, expected-generation compare-and-set, unique operation IDs with payload digest, and transaction-local lock/statement/idle timeouts. A conflicting operation or unified AP/AT identity binding rolls back entirely; a same-payload replay resolves without incrementing a generation. Cross-provider operations cannot read or change another provider's account. A production caller must also be authenticated and authorized through the actual provider; this candidate does not implement that.

## What a real migration would require

1. **Complete distributed Solid and unified-identity bootstrap first.** A four-replica sign-up can still omit preferences and auth/registry links; moving account rows cannot repair missing per-Pod resources. A provider must never acknowledge a fully usable account until WebID, ACL, authentication agent, registry, type-indexes and AP/AT identity are complete and durably checked. This must agree with [PR #134](https://github.com/outlaw-dame/activity-pods/pull/134): `WebID === ActivityPub actor URI`, `did:plc`, and initialized ATProto PDS repository are *mandatory together*, never optional protocol toggles.
2. Map the entire current SemApps auth account and OIDC model. Determine exact ownership of existing username, password verifier, email verification, session, MFA, deletion and account ID. Preserve WebID and DID references without rename/reprovision. Do not invent a new password store or downgrade cryptography.
3. Add an actual **single-authority adapter** for `auth.account` and the provider callbacks, with a protected read-only WebID/RDF projection and an explicit cutover barrier. No dual writes, no simultaneous RDF and SQL account owners. Do not simply replace `accountsDataset` with a PostgreSQL connection string.
4. Before accepting suspend/delete/revoke, commit a deny-first SQL generation fence and synchronously invalidate authentication/session validity at the canonical Solid-OIDC authority; safe handling of unknown commits, partitions, retries and token staleness is mandatory.
5. Export, reconcile and compare complete account records and all linked identity references in disposable restore environments. Enforce same canonical WebIDs, anti-IDOR provider scope and least-privileged SQL roles; use explicit migrations and tested backup/PITR. Cutover only after multi-process 1/2/4/8 load, node SIGKILL, database failover and rollback gates pass.
6. Use measured costs before tuning. Start with 2–4 pool connections per cell (8 cells × 4 = up to 32 plus headroom). Track pool wait, lock contention, p95/p99 account reads/writes, WAL volume, autovacuum, cold-restores, index growth and backup cost. Keep indexed account joins bounded and never perform network calls while holding a row lock.


## November 13 — new signup operation journal on the existing account authority

A second, competing account registry is **not** being introduced. The additive
`paper-account-postgres-candidate-v2-signup-ledger.sql` migration attaches
`signup_operations` to the existing PR #138 `accounts` row using the exact
(provider, account_id) foreign key. Both records are inserted in **one
transaction**, retaining the existing provider/username uniqueness rules. The
journal is still candidate-only; no production account route imports it.

`createCandidate().reserveSignup` accepts only server-assigned UUIDs and
32-byte, provider-keyed, domain-separated HMAC digests of the client
idempotency key and canonical request. It requires a provider/app scope and
explicit HMAC key version. The raw key, email, password, bearer token, account
profile, and private signing material are never persisted. Different-payload
replay is rejected; matching replay returns the original operation without
authorizing another identity RPC. Existing SemApps accounts must still be
checked by the trusted provider before *any* new-account reserve during
activation; this isolated SQL candidate does not query SemApps.

`markSignupMayHaveSideEffects` is a durable **pre-side-effect fence**. The
provider must commit it *before* invoking the first external account/WebID,
PLC or PDS operation. Once fenced, subsequent attempts only observe
`reconciliation_required` and cannot automatically execute that operation
again. A crash between the fence and the RPC may require operator
reconciliation even if the RPC never ran; that is an intentional safety
tradeoff. No automatic TTL releases usernames or operation records.

The underlying PostgreSQL transaction helper now treats a lost or failed
`COMMIT` reply as `ACCOUNT_COMMIT_OUTCOME_UNKNOWN`, discards that connection
and requires read-only reconciliation instead of assuming rollback. The
disposable PostgreSQL 18 acceptance test executes a real commit and then
simulates losing its acknowledgment; it verifies the committed operation
survives and subsequent reservation is recognized as replay. The same
acceptance tests cover concurrent same-handle contention, HMAC mismatches,
provider/app scope and exact backup/restore equality of the operation journal.

**Do not activate new signup using this candidate yet.** The real provider
must connect its authorized grants and single `auth.signup` path to these
durable operations, implement read-only PLC/PDS reconciliation, verify the
signed v3 repository and DID/handle reciprocity, check complete distributed
Solid/SAI readiness, issue fresh auth sessions rather than replaying an old
JWT, and prove node death, PostgreSQL failover, key rotation and release
rollback. The independently protected canonical PostgreSQL permissions and
general-Fuseki-writer isolation gates remain closed. Existing-account
migration is a separate project.


## Read-only Solid verification for a reserved new signup

The merged PR #138 account candidate and subsequent signup journal reuse the
actual SemApps/Solid authority. This independent non-activated verifier was
selectively brought forward from historical PR #134, without importing its
competing PostgreSQL operations table or introducing new account ownership.

`verifySignupSolidReadiness` resolves exactly one provider-scoped signup
operation and its existing account row. It refuses a missing or unfenced
reservation, unbound/non-PLC identity, incomplete local repository marker or
invalid account lifecycle state. It then calls only indexed authoritative
`auth.account.findByWebId`,
`identitybindings.getByCanonicalAccountId`, and
`auth.awaitBootstrapComplete`, requiring matching WebID/ActivityPub actor,
managed-local DID and complete Solid bootstrap. Provider/RDF failures fail
closed. A second PostgreSQL read detects concurrent account transitions
without holding a DB connection across external Solid checks.

**This is an evidence probe, not a completion mutation.** It never marks
`ready`, releases a username, creates keys, replays PLC or migrates
preexisting accounts. A production activation must still atomically seal a
fresh evidence version using one provider-owned writer and durable
revocation/epoch fencing, not trust this read-then-read probe as a
transaction across PostgreSQL and Jena. Other release gates remain closed.

## Disposable proof

`pod-provider/backend/scripts/proof-postgres-account-lifecycle.js` asserts the database begins empty, loads the schema, checks disabled-by-default gating, concurrent same-name reservations, idempotent replays, conflicting replay detection, cross-provider IDOR, unified WebID/ActivityPub/did:plc binding, PDS/repository readiness, negative incomplete-identity cases, failed-transaction rollback, expected-generation fencing, suspend/delete transitions and no idle transaction leakage. CI uses disposable PostgreSQL 18 and isolated pinned `pg@8.16.3` without modifying the production package lockfile.

**Success of these tests is permission to review the candidate—not permission to migrate existing users.** Next implementation after the Solid bootstrap gate is a small provider-auth adapter with real Solid-OIDC/SAI revocation integration and explicit rollback tests, not a platform-wide rewrite.

Related decisions: `docs/activitypods-postgres-account-and-groups-decision.md`, `docs/paper-groups-postgres-moleculer-integration.md`.

## Identity contract and scope of the experiment

One user-facing account means one coherent authoritative login/lifecycle record, **not** one interchangeable protocol identifier. WebID and ActivityPub actor URI are the same absolute URI by design; ATProto retains a different required `did:plc` because that protocol uses DIDs. The database keys both protocol identifiers to the *same* account and stores no second user record. A handle change or DID recovery is a later separately authorized state transition, not a silent new account. `repo_initialized` is only a fixture assertion here; in production this must be a **fresh verified outcome** from the real ATProto repository, not a client-supplied Boolean. Neither a provisional WebID nor a DID without its repository can be returned as an activated unified account. This preserves the current protected RDF identity bindings until one reviewed authoritative migration.


## Production signup release boundary (November 13)

The real ActivityPods-managed signed PDS remains a non-activated candidate.
The normal `auth.signup` action now refuses **all production new registration
before any account, dataset, WebID, signing-key, or PLC side effects**. Setting
`APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP=false` cannot bypass mandatory
WebID/ActivityPub + managed `did:plc` and signed PDS onboarding. Existing
account login, identity records and sessions are unaffected. Isolated
non-production fixtures can still use their explicit test opt-out.

This is a source-controlled release fuse, not an environment flag or a
boolean repository-readiness claim. It may only be replaced following reviewed
and verified integration of a real signed PDS writer/readback, PLC and handle
resolution, the single PostgreSQL operation authority, complete Solid/SAI
consent, privileged Fuseki isolation, crash reconciliation, and real
multi-replica acceptance. No existing-identity migration is in scope.



## Cross-authority new-signup proof (November 13)

The new `new-signup-cross-authority.mjs` candidate correlates a single
provider/app-scoped HMAC operation in the **existing PR #138 PostgreSQL account
schema** with the independently signed ATProto repository and the protected
PG-to-Jena recovery record. It adds **no second account registry**, changes
neither WebID ownership nor the SemApps login path and cannot be loaded as a
production service.

The read-only acceptance sequence is:

1. Read the exact fenced new-signup operation (`reconciliation_required`).
   Require the canonical account row still to be in `provisioning`, with the
   same WebID and ActivityPub actor, one managed `did:plc`, handle and PDS.
2. Resolve and verify the actual SemApps user, protected Jena identity binding
   and complete Solid bootstrap. Match protected PDS and handle explicitly
   against the PostgreSQL account projection, rejecting imported identities.
3. Through the provider-owned signed repository authority, independently
   verify current DID/handle reciprocity, PDS endpoint, signing key, real
   signed v3 CAR/MST/CIDs and persisted native event outbox. Do **not**
   accept a synthetic root CID or `repoInitialized` boolean as evidence.
4. Require the PostgreSQL RDF recovery intent to be `applied`, verify the
   current monotonically fenced per-Pod Jena projection and re-evaluate
   current provider/SAI permission. Match exact signed head/root/revision and
   outbox state across both authorities.
5. Re-read the account and operation generations to reject concurrent state
   changes. No PostgreSQL connection or lock is held during DNS, PLC, Solid
   or RDF calls. The result is `status:'evidence_only'` and
   `productionReady:false`, **never an account-completion mutation**.

A disposable PostgreSQL 18 acceptance executes the candidate with an actual
signed CAR and committed repository/outbox, one shared account journal, and
a PostgreSQL recovery intent. SemApps, PLC and Jena/SAI callbacks in this
joint test are **injected trusted fixtures**, not a real multi-process
production authorization path. Negative checks cover missing repo, missing
RDF projection ACK, wrong app scope, protected handle/PDS drift, consent
revocation, incomplete Solid bootstrap, corrupted CAR and stale generation.
Separate existing real Fuseki and native OIDC acceptance cover their own
interfaces; this test does not silently claim their combination is complete.

The signed-repository PostgreSQL transaction helper also now classifies a
lost `COMMIT` acknowledgment as
`ATPROTO_REPO_COMMIT_OUTCOME_UNKNOWN`, discards the uncertain pooled
connection and requires a read-only signed-head/outbox reconciliation.
Disposable tests perform a **real COMMIT** before losing its reply, proving
that a subsequent replay does not recreate genesis.

**Still before production cutover:** implement provider-owned real signed PDS
XRPC, protected account/SAI grant issuance, canonical PostgreSQL
single-writer completion CAS that atomically persists proof generation,
cross-store revocation epochs and outbox consumer delivery, live PLC/DNS
resolution, and multi-replica kill/restart and cost benchmarks. An
`evidence_only` result MUST NOT bypass the production `auth.signup` fuse.
Existing-account migration remains a separate future phase.


## Ready-transition safety: newly journaled accounts cannot bypass signed release

A read-only signed-repository, Solid and PG/Jena proof does not by itself
authorize a state mutation. The generic `change(kind:'transition_state',
nextState:'ready')` candidate now checks the indexed
`signup_operations` row **inside the same PostgreSQL transaction**, under
the canonical account row lock. If the account was reserved through the
new-signup journal, it refuses `ready` with
`ACCOUNT_SIGNUP_COMPLETION_SEAL_REQUIRED`, including the
`suspended → ready` path. It cannot be bypassed with a reused
`operationId` because the guard executes before transition replay.

The existing candidate `reserve()` fixture without a new-signup journal
retains its separate legacy state-transition test path; it is **not** the
production new-account registration entry point. This distinction is
intentional to avoid migrating or silently adopting existing accounts.

The future provider-only completion operation must be a distinct,
generation-fenced PostgreSQL transaction consuming *fresh, current* signed
repo head and outbox evidence plus the still-valid protected SAI/RDF
revocation epoch, with revalidation before every authority-dependent
operation. It must not accept a caller-created Boolean or the disposable
`productionReady:false` evidence result. Until then, new signup remains
in reconciliation and production `auth.signup` stays closed.


## Durable provider evidence seal — candidate v3

The additive PostgreSQL v3 candidate migration extends the existing
signup_operations journal rather than introducing another account table.
It stores one bounded SHA-256 evidence digest, verified commit/root CIDs,
revision, monotone Jena projection fence, account generation and seal
timestamp. These values form historical proof of the **observed**
cross-authority readiness; they are not authorization tokens or private keys.

The candidate accepts a trusted verifyNewSignupEvidence callback at
construction, never a client-provided proof or key. It calls the previously
merged cross-authority verifier before acquiring database locks, confirms
that it returned evidence_only with productionReady=false and a matching
signup operation, then takes the existing account row lock followed by the
unique signup operation row lock in the SAME PostgreSQL transaction. It
rejects an account generation, lifecycle, WebID, AP actor, managed DID, PDS
origin or journal generation that changed during external checks. Only
then can the journal advance from reconciliation_required to
evidence_sealed with immutable CID/revision/fence metadata.

The new operation cannot mark the account ready, log a user in, mint
identity keys or repeat PLC calls. The existing generic ready transition
continues to reject every journal-backed new account, including a sealed
one; after sealing, any old historical replay returns
releaseAuthorized=false and never renews grants. A lost COMMIT reply uses
the existing unknown-outcome recovery rule and an indexed journal read.

**Still required for production:** replace the injected, disposable proof
dependency with the live provider-owned Solid/SAI and signed PDS authority;
ensure consent revocation is fenced atomically against the final
PostgreSQL completion decision, rather than trusting an old proof; add a
provider-only guarded ready transition with generation CAS and a
multi-replica kill/restart acceptance. No production signup route or
existing-account migration is enabled by this v3 seal.

## Read-only current readiness after completion — candidate

The v4 PostgreSQL atomic completion writes historical, scoped evidence and
marks the new account and signup operation ready in one transaction. A
subsequent idempotent replay must **not** equate that historical status with
current permission. The disposable completion candidate now exposes
`readCurrentReady(scope)` and uses it on all three already-ready replay
branches.

The lookup uses the **existing** indexed
`signup_operations(provider_id, app_client_id, hmac_key_version,
idempotency_hmac)` scope, joins the canonical account and current managed
ATProto identity/consent rows, and rejects missing/ambiguous or non-ready
accounts, absent completion evidence, disabled managed identity, changed
account generation, revoked consent, or changed grant URI/revision. Raw
idempotency keys, passwords, browser-supplied owner IDs and proof booleans do
not select the account.

A single SQL statement observes one current PostgreSQL MVCC snapshot; it is
not a cross-store transaction and **does not** guarantee consent will remain
active after the query. Thus the result explicitly retains
`releaseAuthorized:false` and `canAuthenticate:false`. Final permission
checks must use the live canonical authorization authority at the instant an
operation is authorized, and native Solid SAI consent must still be enforced.

The PostgreSQL 18 acceptance tests query completed accounts, reject a
different application's scope and idempotency HMAC, and prove that **revoking
consent after completion makes both current-readiness and completion replay
fail**. Historical evidence is preserved; it is not rewritten or silently
regranted. The candidate remains disposable-only, and production signup,
hosted signed PDS, migration and account/login release fuses are unchanged.

## PostgreSQL v5: scoped Entryway bootstrap readiness (non-activated)

The additive v5 **candidate** migration adds a single indexed, read-only
`current_bootstrap_proof` function. It joins the existing canonical
`signup_operations` journal, unified `accounts`, managed identity and
consent, signed repository, durable outbox and applied RDF projection.
No new account table, identity writer or authorization token is created.

The call is selected by exact provider/app/HMAC version and the provider's
domain-separated 32-byte HMAC of the original Entryway idempotency reference.
Username, canonical WebID = ActivityPub actor ID, did:plc, handle and approved
SAI app URI are also matched **inside the same query**. Current readiness
requires that the journal and account are both ready, completion and evidence
digest fields exist, current account generation matches completion, managed
identity and consent remain active at the persisted revision, the signed
genesis repo head and applied projection match the sealed evidence, and its
durable native event is unblocked.

A new `paper_account_bootstrap_reader` NOLOGIN role receives USAGE on the
candidate schema and **EXECUTE on only that function**, with no raw SELECT,
INSERT, UPDATE or DELETE on account, grant or repository tables. A dedicated
restricted production login must be provisioned in a separate reviewed
migration; do not reuse the database owner, Jena or general Moleculer user.
The SQL function is SECURITY DEFINER with `pg_catalog` search path and
hardcoded fully qualified table names.

The `postgres-bootstrap-readiness.js` adapter is purposely fixture-only and
requires test mode plus disposable PG18 markers on **each call**. It does not
connect automatically to `provider-capabilities`, `auth.signup`, Entryway,
Solid-OIDC, a public route, or the production service loader. Its results
remain `releaseAuthorized:false` and `canAuthenticate:false`.

This is a **current PostgreSQL snapshot**, not a perpetual grant: a later
SAI revocation can invalidate it. Before production, integrate a genuine
restricted role, durable account reservation/signer, enforce native SAI grants
at protected operation time, verify hosted PDS and genuine PLC/handle
resolution, and resolve the canonical WebID shape (the candidate currently
requires no URL fragment while some legacy Solid WebIDs use `#me`).
Do not open production signup merely because v5 and its disposable tests
pass.

## Entryway provider service wiring — disposable integration

The provider's `provider-capabilities.assertCompletedAccountBootstrap` action
can now **opt in only under test/disposable markers** to the v5 proof. The
ordinary in-memory provider reservation remains a non-production fixture.
The production branch continues to refuse bootstrap and new signup, even
if an internal reader object is accidentally present.

The optional integration uses `APODS_ENTRYWAY_PG_PROOF_DISPOSABLE=confirmed`
with `NODE_ENV=test` and the existing account/repository/completion
disposable markers, a fixed loopback PostgreSQL completion-fixture database,
one provider-scoped app-client URI, SAI app URI and provider ID, an explicit
HMAC key version, and a base64-encoded 32-byte provider-held HMAC key.
It connects lazily through a bounded (max 2 connections) pool with connect
and idle timeouts, never transmits raw idempotency keys to PostgreSQL, and
closes the pool on service stop.

The actual Entryway app-bootstrap service consumes this result. After PG
verification it checks the current `auth.account` local owner, obtains the
Pod storage URL from `solid-storage.getUrl` (never from the untrusted request
alone), confirms the native SAI application registration and AccessGrant
membership, and rechecks the **same PostgreSQL account generation, grant
URI and consent revision** immediately before returning metadata. Mismatched
or unavailable evidence refuses bootstrap; there is no fallback to the
process-local Map after a PG error, and no grant-creating call.

This does not implement a production signup, authentication handoff or
permission lease. PostgreSQL and Solid/Jena cannot be read atomically, and
revocation after the final read still requires enforcement at each
protected operation. A production rollout needs a reviewed migration and
restricted non-superuser LOGIN, real signed hosted PDS authority, full
Solid-OIDC/SAI consent flow, multi-replica crash tests and a separate
release authorization decision.


## November 15 — restricted runtime bootstrap reader (candidate only)

The provider-owned `current_bootstrap_proof` function is the **only** SQL
entry point needed to check a completed new account's current PostgreSQL
identity, signed repository, applied RDF projection, native outbox and SAI
revocation revision. Its reader role
`paper_account_bootstrap_reader` is deliberately `NOLOGIN`.

The provider proof adapter now exposes a concrete privilege preflight and
an opt-in `requireRestrictedReader` policy. When configured for the provider,
its service refuses startup unless the pool login inherits only the
restricted reader authority and can execute the exact proof function.
It checks for absence of superuser, `BYPASSRLS`, database/role creation,
replication, account/journal table read/write, arbitrary schema creation,
and direct access to canonical ATProto authority and repository schemas.
The same probe runs before every later proof read. Database driver errors
are reduced to stable, noncredentialed codes. Connection, statement and query
timeouts bound failed provider access.

The PostgreSQL 18 acceptance creates a **disposable dedicated LOGIN** with
membership in the `NOLOGIN` reader role, proves the exact account lookup
under that connection, and independently verifies that a privileged
migration-owner connection is rejected by the runtime gate. The account
schema is not duplicated, and neither login/session secrets nor new
identities are emitted by the reader.

**Deployment contract:** an eventual deployment must provision a separate
restricted login through reviewed secrets/IAM, grant membership in
`paper_account_bootstrap_reader`, and keep general provider, Fuseki and
migration-owner credentials out of the bootstrap pool. Test-only local DSNs
and passwords in the disposable proof must never be reused. These changes
do not authorize production signup or replace the canonical
Solid-OIDC/SAI consent, signed hosted PDS, PostgreSQL writer or storage
isolation acceptance gates.
