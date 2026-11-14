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
   dataset, not ordinary Pod data or Jena administration.
3. The separate **attestor** can query protected RDF, but receives 401/403
   for protected updates, ordinary writes and administration.
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
