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

## Disposable proof

`pod-provider/backend/scripts/proof-postgres-account-lifecycle.js` asserts the database begins empty, loads the schema, checks disabled-by-default gating, concurrent same-name reservations, idempotent replays, conflicting replay detection, cross-provider IDOR, unified WebID/ActivityPub/did:plc binding, PDS/repository readiness, negative incomplete-identity cases, failed-transaction rollback, expected-generation fencing, suspend/delete transitions and no idle transaction leakage. CI uses disposable PostgreSQL 18 and isolated pinned `pg@8.16.3` without modifying the production package lockfile.

**Success of these tests is permission to review the candidate—not permission to migrate existing users.** Next implementation after the Solid bootstrap gate is a small provider-auth adapter with real Solid-OIDC/SAI revocation integration and explicit rollback tests, not a platform-wide rewrite.

Related decisions: `docs/activitypods-postgres-account-and-groups-decision.md`, `docs/paper-groups-postgres-moleculer-integration.md`.

## Identity contract and scope of the experiment

One user-facing account means one coherent authoritative login/lifecycle record, **not** one interchangeable protocol identifier. WebID and ActivityPub actor URI are the same absolute URI by design; ATProto retains a different required `did:plc` because that protocol uses DIDs. The database keys both protocol identifiers to the *same* account and stores no second user record. A handle change or DID recovery is a later separately authorized state transition, not a silent new account. `repo_initialized` is only a fixture assertion here; in production this must be a **fresh verified outcome** from the real ATProto repository, not a client-supplied Boolean. Neither a provisional WebID nor a DID without its repository can be returned as an activated unified account. This preserves the current protected RDF identity bindings until one reviewed authoritative migration.
