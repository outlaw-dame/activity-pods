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


## Next gate — PG18 ↔ protected RDF crash recovery and fencing (stacked draft)

The candidate now includes an *atomic recovery intent* in the same PostgreSQL genesis transaction as the signed v3 commit/CID blocks and pending native event outbox. A genesis that commits without the RDF intent violates the database transaction; a test injects failure immediately after outbox INSERT and proves complete rollback.

### Safety and concurrency model

- Table 'rdf_projection_jobs' is one row per existing canonical account, with a foreign key to the immutable genesis repo plus both actual CID-addressed blocks. Per-account 'lease_epoch' is a monotone bigint, 'lease_owner' is a random UUID, 'lease_until' uses the **database clock**, and retries are bounded. Two concurrent Moleculer replicas cannot both claim the same current lease because the claim uses one conditional PostgreSQL UPDATE. No PG locks or connections are held across RDF I/O.
- All attempted RDF updates carry the PG epoch and must be implemented by a **provider-owned, atomic conditional Jena writer that persists the fence with repoRootCid/repoRev in the same RDF transaction**. It must reject older leases even if an old worker wakes after the new worker finishes. An ordinary GET/PUT or unchecked upsert is NOT sufficient. The PG18 suite first models this property with a protected atomic in-memory RDF CAS. A separate **real Fuseki/TDB2 disposable** suite now checks the conditional SPARQL update (including conflicting duplicate identities), eight-way contention, stale fences and persistence across a server restart. A combined **real PG18 + real Fuseki** suite exercises crash-after-RDF/before-PG-ACK, competing worker pools, stale writer wakeup, revoked synthetic grants and signed read-back after restart. These do not activate actual Pod LDP resource mutation.
- Before writing and before ACK, the reconciler checks current provider authorization, the canonical WebID = AP actor and bound DID, and signed durable PG evidence (commit CID, MST CID, TID, checked CAR, outbox). It compares the protected RDF record after writing. An exhausted or conflicting job transitions to 'blocked' for manual review; transient failures are retried with bounded exponential full jitter.
- After RDF is applied, PostgreSQL requires the *same epoch, owner, nonexpired lease and exact head CIDs/revision* to mark applied. A crashed worker leaves a leased row; after expiry the next worker increments epoch and replays the **same signed head** without creating another DID or genesis commit.
- The 'readiness' API requires **all three**: cryptographically verified PG repo/outbox, an applied recovery record, and a newly read protected RDF projection matching the exact PG head and current epoch. A PG-only or RDF-only success must fail closed. Completed-state drift triggers a read-only diagnostic, never silent rewriting.
- Unreleased by construction: no production service import, no background scanner, no API route, no automatic backfill. The proof only runs with 'fixtureOnly: true' and an explicit disposable PG18 test marker; NODE_ENV=production disables the reconciler.

### Acceptance / limitations

The dedicated test suite covers atomic rollback, successful projection and durable ACK, eight competing replica objects, a simulated crash after RDF before PG ACK, a stale worker prevented from overwriting a newer fence, bounded transient retry, exhausted retries, missing grants, false-ready drift and identity collisions. These tests include disposable PG18 with a simulated RDF CAS, real Jena Fuseki/TDB2 guarded SPARQL updates, and combined real PG18/Fuseki integration. They are **not** proof of production-ready per-Pod identitybinding updates, SAI revocation, distributed user onboarding, or real relay federation.

Remaining blockers before live deployment:

1. Integrate the **tested conditional Fuseki/TDB2 RDF update** with actual protected per-user ActivityPods LDP identitybinding graphs and datasets. Add the fence predicate to the JSON-LD/DTO schema; verify URI-to-graph resolution, provider-only SPARQL execution and SAI-grant version fencing. Invalidate or synchronize any LDP/JSON-LD indexed projections; eliminate unfenced 'upsertRepoBootstrap' writes on the new path.
2. Wire the candidate through the reviewed mandatory unified signup and verified-repo branches (#134/#140), with provider-only capability minted inside trusted ActivityPods code and no public signing bypass.
3. Extend the disposable real-PG/real-Jena **four-worker contention, injected process-crash and persistent-restart** acceptance to full multi-process/four-replica **Pod-dataset** integration with real process SIGKILL, Solid-OIDC/SAI grants and revocation races. Test long pauses, provider partition, lease renewal and live DID/key rotation.
4. Add a production PG schema migration with least-privilege roles, replication/backup/restore, observability, paginated claim queue, rate/connection budgets and zero-downtime rollback. Test actual duplicate delivery and immutable native outbox publishing.
5. Only after the above and protocol writes/XRPC/relay acceptance pass, authorize a separate production activation PR. Never equate a green disposable CI proof with a live PDS.

### Cost and performance constraints

- Keep a **single** recoverable row per account per genesis, not a per-request history or duplicated identity graph. One partial pending index and one partial expired-lease index are sufficient for the initial bounded worker; watch their write amplification in production. Do not scan an entire account population on each restart.
- Use a bounded PG connection pool across Moleculer replicas, short DB transactions and per-account leases. No network, crypto signing or Jena writes inside PG locks. Prefer at-least-once idempotent replay to two-phase distributed blocking transactions.
- Cap retry attempts and use jitter; avoid tight failure loops and unbounded in-memory queues. Metrics should summarize lease contention, stale-fence rejections, job age and blocked jobs **without logging identity keys, private data or raw CAR bytes**.


### Real Jena + real PostgreSQL evidence (still NON-ACTIVATED)

The dedicated workflow now includes two independent mechanisms and a combined test:

- The local PostgreSQL 18 and signer proof validates durable genesis/outbox/recovery intent and epoch-owner lease completion.
- The real 'semapps/jena-fuseki-webacl' TDB2 fixture tests an atomic SPARQL 1.1 DELETE/INSERT WHERE guarded by canonical WebID/AP/DID/source/status, **absence of conflicting duplicate claims**, an immutable root CID/revision, and strictly increasing numeric lease fence. Both default and named graph variants are tested. HTTP 2xx cannot be treated as successful CAS; the caller must read back and compare every required predicate. The test restarts the persistent Fuseki store to verify durability.
- The combined PG18 + TDB2 fixture uses **independent PG pools** to simulate four Moleculer workers and tests lease arbitration, process-crash simulation after RDF write/before PG ACK, epoch+1 retry, stale writer no-op and refusal to ACK a superseded epoch, and full signed PG/RDF state after the Fuseki restart. The fixture key is generated at runtime in the CI runner's temporary directory (permissions 0600) and deleted after verification, never checked into source or stored in PostgreSQL.

This proof uses synthetic bindings in the disposable 'settings' dataset, not actual ActivityPods per-Pod protected LDP identitybinding graph placement. It also uses a stub authorization decision, not live SAI consent enforcement. Thus **actual runtime activation and automatic user account repair remain blocked.**


### Integration audit: real ActivityPods identitybindings vs synthetic Fuseki fixture (2026-11-11)

The *real* 'pod-provider/backend/services/identitybindings.service.js' is a 'ControlledContainerMixin' resource stored under the canonical account WebID's own container. It is NOT the globally indexed 'settings' RDF view. The 'settings' data is a lookup **projection**, and may not be used as the source of truth for readiness or atomic account updates. Its live location is computed from 'identitybindings.getContainerUri({webId})' plus a SHA-256 canonical-account-based slug ('atproto-' + first 24 lowercase hex chars). A production writer MUST resolve the exact binding dataset/graph through SemApps resource location rules, not infer it from the path, assume the 'settings' graph, or expose a caller-selected graph.

The current LDP 'identitybindings.upsertRepoBootstrap' delegates to an unfenced resource upsert. It must NOT be called concurrently with a fenced RDF writer and must NOT be used as a production repository-ready transition until its compare-and-set semantics and JSON-LD projection invalidation are redesigned. The existing DTO currently exposes 'repoInitialized', 'repoRootCid' and 'repoRev' but **does not expose 'repoProjectionFence'**; the real context/ontology and indexers need this field and an exact typed lexical representation before integration.

The synthetic Fuseki fixture intentionally models direct triples with 'webId'/'activityPubActorId' as URI nodes and 'canonicalAccountId' as a literal. A real Solid/JSON-LD resource may encode these properties as IRIs or literals depending on its installed context. The tested SPARQL guard compares 'STR(...)' values across those representations, but production must verify real live resource serialization and end-to-end LDP reads before writing anything. The installed ontology and graph conventions must be checked against SemApps on the exact provider version. No speculative default or named graph selection is permitted.

Further safety concerns:
- The current recovery ledger is deliberately a *genesis-only candidate* ('generation=1'). A production PDS would need a separate versioned repository-head update protocol and appropriate key rotation handling.
- A bounded lease and monotone RDF epoch protect *completed* projections against stale writers; a lease expiry cannot interrupt an already in-flight RDF request. The PG ACK must therefore remain fenced and readiness must recheck current evidence. Before activation, evaluate cancellation and stale-grant protection at the **RDF mutation boundary**, not only before issuing it.
- Pending jobs whose attempt count has already reached the policy limit are now transitioned to a terminal 'blocked' status. An attempt-exhausted pending row must never produce an infinite 'busy' response.
- The failure history must be distinguished from current CI: earlier intermediate work had a missing 'resolveDelegatedIdentity' injection and an isolated PG connection exhaustion; their later exact-head workflows passed. Only cite the current head's checks as an acceptance result.


## Per-user ActivityPods Solid-OIDC/SAI atomic projection acceptance (stacked draft #144)

This candidate does NOT register a production repository writer. It requires fixtureOnly:true, ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE=confirmed and nonproduction context. It establishes an integration boundary, NOT live Solid-OIDC/SAI approval.

### Actual ActivityPods routing (not settings-index authority)

pod-activitypods-adapter.mjs resolves a canonical account using a bounded SELECT from the SemApps settings AuthAccount type (LIMIT 2, rejecting duplicate WebID owners), then uses solid-storage.getUrl and identitybindings.getContainerUri; verifies the existing per-user Jena dataset matches the account username and constructs the existing per-WebID binding URI (atproto- + first 24 lowercase SHA256 hex digits of canonical WebID). User-selected datasets, cross-Pod URLs and unrelated origins are rejected. The global settings index is only lookup data, never canonical identity authority.

pod-per-user-live.mjs creates an actual persistent username-named TDB2 dataset, inserts LDP-shaped binding and exact SAI AccessGrant/DataGrant RDF, tests atomically guarded projection, monotone deny-first revocation, durable read-back after Fuseki restart, and real Jena parsing of the bounded keyset pagination query. The real Moleculer action names are dispatched through test doubles, and the OIDC verification action returns a synthetic test claim. This is NOT yet an end-to-end deployed SemApps / Solid-OIDC test.

### Authorization chain

1. Provider-only 30-second SHA256 HMAC operation tickets bind the canonical WebID, DID, app URI, access grant URI, consent epoch and operation; project tickets also bind signed root CID and repo revision. The issuer remains private trusted provider code. No generic API action, inherited ctx.meta or caller-supplied provisioning grant can mint it.
2. Existing jwk.verifyToken validates JWT cryptographic authenticity and expiry; the adapter additionally enforces exact issuer, subject, audience, authorized party, recent issuance and nonexpiry. The current provider issues long-lived ID tokens: an unexpired token alone is not proof of current consent. Real session revocation and client-ID-to-SAI-app mapping remain release blockers.
3. Exact owner-scoped access-grants.get and data-grants.get reads compare WebID, app, configured managed-repository SAI shape and write rights. No grants list, auth.account population, account-wide scan or per-Pod fanout is permitted on the hot path.
4. The repository SPARQL CAS and active same-epoch consent condition share a single per-Pod Jena update transaction. Deny-first revocation atomically changes status to blocked and increments the consent epoch in the same dataset. A stale epoch cannot create a newly accepted projection after the revoke transaction.
5. A SPARQL HTTP 2xx does not imply that the guarded WHERE matched: post-write projection verification re-reads the protected LDP binding (including strict canonical positive integer fence), active consent, current SAI grant and verified OIDC claims. A revoked grant must cause projection verification to fail even if previously committed CID triples remain in RDF. The adapter never returns ready:true: repository readiness additionally requires the separately proven PG18 signed CAR/MST/DID key, outbox and durable ACK at the identical head.

### Unreleased, critical acceptance blockers

- Full SAI pre-mutation hook coverage is NOT wired. access-authorizations, data-authorizations, access-grants, data-grants and app-registrations delete/upgrade/rollback paths can change rights. Before deploying, every relevant mutation must persist deny-first blocked consent BEFORE changing the SAI authorization; account for crashes and idempotent retries. The isolated adapter revoke() is an atomic primitive, not full provider lifecycle integration.
- The signer/PG issuance side is not yet linked end-to-end: privileged provider code must verify the canonical DID key, CAR/MST signature, CID blocks, immutable PostgreSQL native outbox and recovery lease and then issue the exact root/revision operation ticket. The current CI exercises these components in separate fixtures.
- Graph selection, real JSON-LD serialization/context, SemApps LDP caching/registry and per-Pod resource targeting must be verified against the installed provider versions. Test four real process replicas with SIGKILL/partition, lease expiration, grant revocation and real signed Solid-OIDC tokens. The real Fuseki fixture uses synthetic Moleculer dispatch, not a deployed SemApps runtime.
- OIDC OAuth client IDs may differ from SAI app agent URIs. The candidate requires equality and fails closed until a trusted, auditable mapping is provided. Never relax this using arbitrary caller parameters.
- Atomic consent gating only prevents grant-race writes if ALL grant mutations fence the permission ledger first. Post-write rechecking can withhold readiness but cannot make unauthorized earlier writes disappear.
- A separate reviewed production migration, least-privilege PG/Jena roles, outbox delivery, signature/key rotation, metrics and zero-downtime rollback must precede activation.

### Scaling contract

Each repository operation is restricted to one max-two-row canonical account SELECT, a fixed number of exact SAI grant reads, one Pod-specific Jena CAS, and bounded readbacks (each Moleculer call has a 5-second budget). No unbounded Pod enumeration, auth.account.find population sweep, all-graph scan, N+1 cross-Pod calls or PostgreSQL lease held during network I/O is permitted. Measure P50/P95/P99, Jena/PG connection budgets and latency under multi-replica workloads before enabling an API. The settings binding index now uses server-side keyset pagination, but bulk exports still need an explicit snapshot-consistency plan.


### Upstream SemApps/Moleculer scaling risk avoided

Source inspection of SemApps auth account (src/middleware/packages/auth/services/account.ts) and TripleStoreAdapter (src/middleware/packages/triplestore/adapter.ts) found auth.account.findByWebId invokes an unbounded CONSTRUCT query and frames the result as JSON-LD without SPARQL LIMIT. Work can expand under duplicate WebID claims, account schema growth or settings corruption. This candidate instead issues exactly one predicate-constrained SELECT ?account ?username LIMIT 2 against the real semapps:AuthAccount, semapps:webId and semapps:username settings model, and rejects zero/two owners, malformed account URNs and invalid dataset usernames. Production must verify this exact RDF serialization against the installed SemApps dependency version. An ontology change must fail closed rather than trigger account enumeration; existing public account APIs are unchanged.


## Integrity correction: PG recovery lease vs Solid/SAI consent revision

**These are separate monotonic counters.** PostgreSQL 'rdf_projection_jobs.lease_epoch' is a worker fencing token which advances after process crashes, lease expiry and retries. The per-Pod Jena 'repoConsentRevision' represents the current SAI grant lifecycle; it does NOT advance merely because a PostgreSQL recovery worker must replay the identical cryptographically signed repository head.

The candidate per-Pod projection API now carries 'projectionFence' (exact PG lease epoch) separately from 'epoch' (consent revision). The provider-issued HMAC operation ticket has been versioned to 'paper.atproto.pod-projection.v2' and covers both values together with the account/WebID, DID, app, grant URI, operation and exact signed CID/rev. v1 tickets do not authorize v2 writes. The Jena DELETE/INSERT WHERE CAS compares and persists 'projectionFence' on the identitybinding while checking an unchanged active 'repoConsentRevision' and exact grant URI *within the same TDB2 update transaction*. Readiness must compare the correct counters against their independent authoritative sources.

This distinction matters for multi-replica durability. For example, PG worker A can commit RDF fence 1 then crash before PG ACK. Worker B claims lease fence 2 while the same user grant still has consent revision 1. A correct recovery advances the same immutable RDF signed head from fence 1 to 2 without mutating/reissuing the SAI grant, then ACKs PG lease 2. Conversely, revocation changes consent revision 1 to blocked revision 2; PG worker epoch 3 must be denied, even with a valid old operation ticket.

**Additional production hardening gates:** the provider must mint v2 tickets only from a current, authoritative PG claim; never accept an app-provided lease number. All native SAI authorization/grant create, update, delete, reinstall, revoke and fallback paths must be fenced before mutation. A test fixture with stubbed SAI/OIDC is not a substitute for that wiring. Proof tests should pair this replay with the existing real PG18 recovery state, and confirm no false-positive readiness after grants change, worker restart, LDP indexing lag or revoked grant. Avoid unbounded retries and account scans.


### Solid-OIDC token conformance (spec-sensitive)

The per-Pod proof now requires a real Solid-OIDC ID-token audience array containing both the application client identifier (the 'azp') and the special 'solid' audience, along with a syntactically valid DPoP confirmation thumbprint ('cnf.jkt'). A conventional app-only ID token is not sufficient for this permission path. The fixture explicitly rejects app-only, missing-'solid' and unbound tokens. Source: https://solid.github.io/solid-oidc/ (Token Instantiation and DPoP-bound OIDC ID Token).

**The native 'jwk.verifyToken' action currently checks signed JWT validity, NOT the request's DPoP proof.** Checking the 'cnf.jkt' field makes token shape stricter but does not establish proof of private-key possession. The native Solid-OIDC OP's emitted audience/cnf claims and the resource server's DPoP verification must be tested end-to-end (including method/URL, replay, nonce and key thumbprint). Do not activate this candidate by just enabling its feature flags.

## Disposable PostgreSQL canonical-storage privilege boundary (November 2026)

The `pg-private-authority-proof.mjs` acceptance uses two **independent
PostgreSQL LOGIN credentials** with new, randomized disposable roles.
The ordinary/general-service role can resolve the private schema but cannot
SELECT, INSERT, UPDATE, DELETE or TRUNCATE canonical consent, cannot create
objects in the schema, and cannot assume the authority-writer role.
The dedicated authority role can insert and atomically block consent but is
explicitly denied DELETE. The proof reads back canonical state after the
attempted unauthorized operations. It uses SQLSTATE 42501 from a real
PostgreSQL 18 service, not an in-process mock or a privileged SET ROLE test.
Its temporary schema and roles are destroyed afterward; credentials are
generated in memory and not logged or stored.

**This is a least-privilege proof, NOT production integration.** The real
ActivityPods `triplestore` service still has direct privileged access to the
live Fuseki dataset used for identitybinding and SAI, so a general Fuseki
SPARQL update remains able to bypass LDP hooks. No actual canonical consent
migration, runtime role wiring, signed writer, default-deny production SQL
deployment or recovery protocol is enabled here. Next, wire a separately
authenticated canonical authority with fail-closed versioned revocation and
prove that the real general-provider credential cannot write it; project
non-authoritative RDF views separately with causal fencing and reconciliation.
Only then reconsider the protected writer source-controlled release fuse.
