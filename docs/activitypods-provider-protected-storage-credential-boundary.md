# ActivityPods managed ATProto: real provider protected-storage boundary

**Gate:** storage credential segregation and authority mapping.
**Status:** nonactivated, fail-closed. Production signup, managed PDS,
native SAI and per-Pod identity binding cutover remain **NO-GO**.

This document is based on the actual provider service wiring, not only the
synthetic protected-TDB2 fixture. It is the next step after merged #207–#209
(independent RDF attestation, automatic recovery/readiness and strict
RDF-shape validation). No new identity provider or duplicate DID signer
is introduced.

## Verified current provider data flows

| Operation | Real source path | Current storage/authority |
| --- | --- | --- |
| Generic SPARQL query/update, dataset actions | `backend/services/core/triplestore.js` | `@semapps/triplestore` with `CONFIG.SPARQL_ENDPOINT`, `CONFIG.JENA_USER` and `CONFIG.JENA_PASSWORD`; one privileged provider credential context |
| New Solid user Pod dataset | `backend/services/solid/storage.js` | `dataset-provisioning.ensureSecureDataset(username)`, then `ctx.meta.dataset=username`; ordinary SemApps LDP creates Pod storage root |
| Dataset creation/bootstrap | `backend/services/core/dataset-provisioning.js` | Direct Fuseki `/$/datasets` and named-graph `triplestore.update`, using the **same** Jena credential source as normal SPARQL |
| Canonical user-facing binding | `backend/services/identitybindings.service.js` | Per-WebID `ControlledContainerMixin` LDP resource in username dataset. Legacy upsert/remove use whole LDP resource mutation; the current fence guard refuses observed fenced entries but cannot eliminate a read/PUT race |
| Binding lookup index | same service | `settings` SPARQL index for efficient DID/handle discovery, **not** canonical WebID/consent authority |
| SAI grant and authorization records | `backend/services/sai/{access-grants,data-grants,access-authorizations,data-authorizations,app-registrations}.js` | Per-Pod LDP `ControlledContainerMixin` paths, many with `webId: 'system'`; pre-hooks call `beforeSaiMutation` when enabled |
| User account provisioning | `backend/services/unified-account.service.js` and `backend/services/core/atproto-provisioning.js` | ActivityPods account/WebID/ActivityPub and managed DID provider; no production release |
| Provider canonical identity/consent control | `backend/utils/atproto-canonical-pg-authority.js` and restricted PG18 migrations | PostgreSQL 18 exact owner/DID, grant/revision and revocation, no authority from user-controlled SPARQL |
| Independent signed repository + projection | `backend/candidates/atproto-signed-repo-proof/` | Signed repo/blocks/intent in PG18, isolated per-head receipt plus a separately credentialed read-only RDF attestor; not registered on production services |

The legacy `backend/services/core/ldp.js` hooks forbid general LDP
mutations to `identity-bindings` while the native SAI fence is enabled.
**These hooks do not stop an existing SemApps triplestore login from
directly issuing privileged SPARQL updates against the same dataset.**
Similarly, WebACL read permissions do not imply graph-level isolation of
privileged SPARQL Update.

The shared global Jena credential also lives in the dataset administrator
path. Merely placing two usernames in one backend container or calling
a different action name is **not** a storage-level isolation boundary:
a compromised ordinary backend that still has the administrator secret
can use it to bypass an apparently restricted client.

## Narrow admission proof added by this gate

`provider-storage-credential-admission.mjs` supplies a strictly
disposable, real-HTTP privilege check using the same expected identities
as the actual provider's eventual separate processes:

1. The **ordinary** provider credential can query and issue harmless
   no-op SPARQL updates to its own TDB2 dataset, but gets authenticated
   401/403 denials for protected query/update/alternate endpoints and
   Fuseki dataset administration.
2. The separate **projector** can query and update only the protected
   dataset. Both ordinary Pod **queries and writes**, and administration
   routes must be denied; merely preventing ordinary writes is inadequate
   because user Pod data may be private.
3. The separate **attestor** can query protected RDF, but receives 401/403
   for protected updates, ordinary Pod **reads and writes** and
   administration. This read-only permission is restricted to *protected*
   RDF; it is not general read access to other users' Pod datasets.
4. Duplicate principals, shared secrets, an administrator used as an
   ordinary login, a projector/attestor supplied as the ordinary login,
   a wrong password, public/non-loopback origins and production invocation
   are rejected. The preflight runs before and after a persistent restart.
5. All privilege probes use a random, never-existing subject and a
   no-op SPARQL DELETE WHERE; they do **not** delete or overwrite real
   protected triples merely to determine whether an overprivileged account
   can write. A 404/405 or redirect does not count as a security denial.
   Network requests have deadlines and never log credentials or tokens.

**Test outcome is a credential-configuration acceptance only.** The
disposable fixture currently uses distinct Jena Shiro roles and datasets.
The real SemApps provider does not yet use that role split. Passing this
test must **not** be interpreted as a successful production cutover.

## Ordered implementation plan (no drift)

### P1 — Extract dataset administration out of the ordinary backend

- Introduce a purpose-built *provider-owned* dataset-creation service in
  its own process/secret and network scope. It should accept only a
  signed, one-time account creation claim and a canonical, collision-
  checked username from ActivityPods (never a caller-supplied arbitrary
  dataset name, admin command or SPARQL).
- Replace direct general-backend `/$/datasets` calls with a narrow,
  idempotent create/verify contract and bounded retries. At rest, the
  ordinary backend must **not possess** the admin password or unrestricted
  network route. Evaluate a separate admin startup job if acceptable for
  onboarding and existing restore workflows.
- Preserve `settings` and per-user LDP/WebACL initialization. Verify
  clean creation and replay/idempotency across two concurrent signup
  processes. Avoid a dataset-per-protocol strategy or additional
  per-account database connection pools.

### P2 — Protected binding and consent physical separation

- Choose a supported Jena version/write-isolation mechanism after
  auditing the existing SemApps `jena-fuseki-webacl` implementation.
  The disposable image uses Jena 3.17.0 / Java 8, not an approved current
  production runtime. Jena 6 removed historical webapp/permissions
  components; compatibility and migration must be explicitly proven.
- Give the ordinary provider strictly *ordinary* Pod access, the
  provider-owned projector a narrow monotone-CAS mutation operation,
  and the independent attestor read-only access. A protected dataset
  and network security policy, or equivalently auditable write-aware
  storage gate, must reject ALL ordinary SPARQL/Graph Store/admin paths.
- Maintain one ActivityPods WebID/AP/DID identity authority. Do not
  create a second user account or duplicate DID signer. Treat
  `settings` as a replaceable index. A protected canonical binding
  cannot be replaced by a stale LDP PUT, even during bootstrap, rollback,
  deletion, account repair, revocation or concurrent retry.
- Reconcile LDP identity DTO and SAI grants with protected canonical
  storage through an explicit atomic provider mutation API. Never
  silently produce two authoritative sources of consent or binding.
- Keep protected ownership rooted in ActivityPods account creation and
  SAI authorization, while PostgreSQL retains signed repository and
  canonical revocation/lease authority.

### P3 — Live provider acceptance and release decision

- Wire the real provider service registrations and independent secret/
  network scopes; run the existing real-provider HTTPS/SAI workflow
  together with signed PG18 and persistent Jena/TDB2 acceptance.
- Exercise owner registration, consent grant replacement/deletion,
  partial signup, cross-account collisions, expired claims, revoked
  credentials, forged actor/WebID/DID, concurrent legacy PUT/DELETE,
  direct privileged SPARQL and Graph Store mutation attempts, process
  kills, Jena restart/restore, PostgreSQL failover, multi-replica
  state convergence and nonreplayable native outbox.
- Require no false-positive readiness after drift or revocation.
  Measure p95/p99 latency, SQL/Jena round trips, Redis load, queue
  growth, RSS, resource limits and operating costs.
- Only a later source-reviewed release may remove the
  `NATIVE_PROTECTED_STORAGE_RELEASED = false` fuse in
  `backend/services/utils/atproto-production-release-gate.js`.
  Do not use environment flags to override this release gate.

## Source-of-truth invariant

ActivityPods remains the sole provider of account, WebID and ActivityPub
identity, managing the ATProto DID binding. The independently signed
repository and canonical grant/lease authority live in PostgreSQL; only
the trusted projection layer can materialize a current binding into
protected Jena storage. The conventional per-Pod LDP resource and
global settings index must never become an alternative grant authority
for managed-ATProto actions.

The storage proof is an O(1), startup-oriented credential check. It does
not scan Pods, allocate a pool per user, open a cross-store SQL transaction
or add a mandatory per-request credential probe.

## P1a — signed pre-account dataset creation (nonactivated integration)

The actual `auth.signup` action calls
`dataset-provisioning.ensureSecureDataset(username)` **before** it creates
and attaches the WebID/account. An out-of-process administrator cannot
safely authenticate a creation request by requiring a *completed* WebID:
that would introduce a circular dependency. Conversely, accepting an
unverified `dataset` string directly on a privileged admin API would let
any compromised ordinary provider create arbitrary Jena datasets.

The additive `dataset-admin-claim-service.mjs` candidate therefore proves
a **pre-account reservation contract**:

- A trusted ActivityPods reservation issuer, separate from the ordinary
  SemApps SPARQL process, signs a deterministic, fixed-schema Ed25519
  claim for a single canonical username, owner WebID, unique reservation
  and nonce, short expiry, explicit audience and issuer. The sidecar
  receives only the issuer's public verification key; the ordinary
  provider gets **neither** the issuer signing private key nor Fuseki
  administrator secret.
- A PostgreSQL 18 table stores **one immutable ticket digest per dataset**.
  The separate SQL LOGIN has strictly column-scoped rights to insert
  the claim, read bounded claim fields and update only completion state.
  Direct dataset/owner/ticket updates, forged precompleted claims,
  DELETE/TRUNCATE and role escalation are refused by both SQL GRANT and
  startup admission.
- A separate disposable administrator process performs *only* verified,
  fixed-form TDB2 dataset creation using its own Fuseki admin credential.
  It never receives arbitrary SPARQL, graph names, Fuseki routes, HTTP
  verbs or administrative command bodies from the ordinary caller.
  Database mutations commit **before** network I/O: there is no cross-
  store transaction held open during Jena requests.
- Concurrent identical requests may race safely through Fuseki's create
  conflict but converge on one PG row. After a crash, the same immutable
  signed ticket may retry until its bounded expiry. A different signed
  claim for the existing dataset is rejected, even with a valid issuer
  signature. A Fuseki HTTP 2xx/409 is not considered enough; the provider
  checks the newly created dataset's actual SPARQL endpoint and confirms
  it is empty across the default **and all named graphs** before making
  the completion durable.
- All routes, credentials, SQL endpoints and account URI mapping are
  hardcoded **only for disposable loopback CI**. The test also rejects
  forged/mutated/expired claims, wrong owner, unsupported verbs, oversized
  requests, column-grant escalation, and verifies persisted status after
  independently restarting both the admin child process and Jena TDB2.

**Release limitations:** the trusted reservation issuer is only a
test fixture, not yet part of live ActivityPods `provider-capabilities`
or `auth.signup`; the sidecar runs as an independently credentialed
test child, not a fully isolated production container or service
account. The test-only PG role/credential is not the deployment policy,
and the current ordinary backend continues to possess the legacy Jena
admin secret. This gate does not release production signup, native SAI,
the protected resource's physical separation or Jena major-version
migration.

**Next required work:** move the issuer private key into trusted
ActivityPods account reservation authority, bind reservation to the
canonical username before any dataset creation, launch the administrator
under a genuinely separate container/user, secret and network namespace,
replace the real provider's `createDatasetViaFusekiAdmin` with a
timeout-bounded authenticated client to this narrow service, remove
Jena admin credentials from ordinary SemApps processes, and run a
live multi-replica Solid signup + grant/revocation acceptance. Only
after that pass should a separate review consider production release.

## P1b — actual provider service delegates creation in disposable acceptance

`backend/services/core/dataset-provisioning.js` now has a **test-only**
delegation branch calling the shared `backend/services/utils/atproto-dataset-admin-delegation.js`
client. The change occurs before *any* triplestore existence check or
admin fallback. When enabled by the exact disposable testing combination,
the service requires the explicit operation-scoped `ctx.params.datasetAdminTicket`, checks exact
reservation scope and forwards the signed ticket to a fixed, local
`POST /v1/provision` endpoint; only the independently credentialed
administrator checks its Ed25519 signature and one-row PostgreSQL claim
ledger. Success requires a strictly typed, bounded acknowledgment.

The real service continues using SemApps' existing
`triplestore.dataset.waitForCreation` and
`ensureSemappsNamedGraphs` sequence after successful delegation.
A denied or unavailable administrator **does not** fall back to
`triplestore.dataset.create` or the legacy Fuseki admin endpoint.
The existing legacy branch is unchanged when delegation is off.

A separate subprocess executes the **same CJS client as the real
Moleculer action** against the actual PG18/Fuseki service from #211.
Its environment contains only seven disposable ordinary-provider
parameters and a signed ticket. It does not receive the SQL
administrator DSN, Jena admin password, agent credential, signing
private key or a triplestore management connection. It tests signed
creation replay and rejects missing or cross-dataset claims, including
after restarting both the administrator process and persistent Jena.
The ticket is deliberately **not** placed in inheritable Moleculer\n`ctx.meta`; nested triplestore, LDP and WebACL calls receive only their\nordinary arguments, not the signed creation capability. The backend\nunit suite independently exercises the actual
`dataset-provisioning.ensureSecureDataset` action, verifying that
delegation precedes triplestore existence checks and preserves its
ordinary LDP graph-initialization behavior.

**This does not release production.** The client refuses execution
outside disposable Node tests or when *any* of the known privileged
administrator/issuer credentials are present in the ordinary process.
The live provider's `CONFIG.JENA_PASSWORD` and startup network
layout have **not yet been physically removed**, and the trusted
account-reservation issuer has not yet been integrated into
`provider-capabilities` or `auth.signup`. The latter service still
creates the dataset before account creation; new production signup
remains NO-GO. The ephemeral subprocess and hardcoded loopback
credential policies are acceptance evidence, not a production
deployment blueprint.

Next: use a trusted, durable pre-account reservation in the real
ActivityPods account lifecycle; run dataset-administrator and ordinary
provider in isolated network/secret scopes; remove Fuseki admin
password from all general SemApps processes; verify actual Solid
WebACL/bootstrap behavior with distinct storage roles; then run
multi-replica crash/retry, private SAI grant/revocation and latency/cost
proofs before changing the source-controlled release fuse.

## P1c — PostgreSQL 18 canonical pre-account reservation fence (disposable)

The service-local `provider-capabilities.idempotencyRecords` and
`dailyUsage` Maps are **not** an authoritative multi-replica account
lifecycle. They are still present only for the legacy test path; production
`reserveAccountProvisioning`, `auth.signup` and
`unified-account-api.create` **remain closed**. Nothing in this
candidate replaces the ActivityPods WebID/ActivityPub identity owner.

`pg-preaccount-reservations.sql` now implements a real PostgreSQL 18
ledger and per-app UTC-day quota table behind narrowly granted
`SECURITY DEFINER` operations. Provider + approved app + idempotency
hash determine the request scope; username and expected WebID have
independent database uniqueness constraints; completed ActivityPub actors
and ATProto DIDs are also globally unique across reservations. PostgreSQL advisory
transaction locks serialize only **same-key** contenders; unique indexes
resolve cross-key/cross-app username races. Quota reservation and new
username insertion are in one subtransaction, so rejected uniqueness
collisions **do not consume quota**. Key and request fingerprints are
stored as 32-byte hashes, not plaintext credentials.

The first successful reservation returns a UUID and **one-time fence
token**. Retrying the same key, even from another provider replica, only
returns an in-progress/completed state **without the fence**. The
`start_side_effects` transition consumes the fence under an unexpired
120-second database-clock lease **before any dataset/WebID/DID operation**.
If the worker dies after that transition, the username is permanently
held for reconciliation; no restart, TTL expiry, retry or different app
can mint a second identity. A second `complete` cannot overwrite the
already finalized identity. Completed rows hold bounded non-secret
identity identifiers and an evidence digest, not JWTs or replayable
signup responses. Expired **unstarted** reservations also remain fenced
until an explicit, separately audited recovery protocol exists.

The issuer is separately credentialed: the worker role can call only
`reserve`, `start_side_effects` and `complete`; the issuer role can
only check a specific live username + expected WebID + reservation UUID
+ fence for a short-lived signed dataset claim. Neither role may select
or directly mutate the tables. Process-child environments are explicit
allowlists; PostgreSQL superuser DSN, Fuseki admin password and Ed25519
signer private key are **not** copied to worker/issuer test children.

`account-reservation-live.mjs` is wired into the real PostgreSQL 18
+ Jena disposable CI. It uses independent PostgreSQL sessions to race
eight same-key reservations, checks first-writer uniqueness, atomic
daily quotas, cross-app username conflicts, mismatched fingerprints,
forged fencing tokens, expiry with no lease takeover, and mutation
before/after a restarted process. It tests a real Ed25519 dataset claim
**only after** a separate issuer credential positively checks the
matching reservation; SQL injection by direct table access and eleven
privilege-drift configurations (including TRUNCATE, MAINTAIN,
pg_read_all_data and column-specific SELECT/UPDATE/INSERT/REFERENCES grants)
must fail closed. Admission checks effective *any-column* privileges, not
just table-level permissions, to prevent fence-token disclosure. After simulated crash/restart,
a second account must not complete with another account's DID or
ActivityPub actor.

**Not yet activated:** This proves durable *reservation semantics* and
issuer eligibility, **not** a complete trusted signer process, the
actual `provider-capabilities`/signup integration, verified account
ownership, signed PDS receipt validation, client reauthentication for
completed-account replays, production deployment credential isolation
or a recovery operator. The test-only SQL `complete` operation checks
an evidence hash **shape**, not cryptographic evidence; it must never
be treated as production evidence verification. The test hardcodes an
isolated `paper.example.org` provider identity and disables all
production execution by source-controlled and explicit fixture gates.

**Next release dependencies:** Bind this PG reservation directly to a
provider-authenticated `unified-account-api` grant and the actual
`auth.signup` pre-dataset admission (no untrusted grants in forwarded
Moleculer metadata). Make the trusted issuer check the PG reservation
*itself* before signing; isolate its private key from ordinary providers.
Require real Solid WebID/AP bootstrap + signed PDS repo attestation
before the irreversible `complete` transition. Add auditable,
human-authorized recovery for stranded pre-effect leases; do **not**
auto-release unknown outcomes. Remove Jena administrator credentials
from ordinary provider processes, prove native protected-storage
isolation and SAI revocation, and measure two-replica load and cost
before considering the source-controlled production release change.
