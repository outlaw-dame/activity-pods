# Paper Groups G1 — SAI Revocation/Reservation Commit Fence

Status: **design gate; not implemented**  
Scope: `outlaw-dame/activity-pods`, PR #117, `feat/collectives-g1-authority-boundary`  
Updated: 2026-11-09

## Decision and safety invariant

Paper's Group authority lives with the **Pod provider**, not a user's Pod, the UI, the Fedify sidecar, or an ATProto PDS. Authentication continues to use the existing **Solid-OIDC** infrastructure. Consent continues to use **Solid Application Interoperability (SAI)**; group capabilities `apods:CreateGroup` and `apods:ReadGroups` are **not WebACL file/collection rights**. Do not introduce group-specific passkeys, a new login flow, or a separately trusted client issuer.

**Required invariant:** If an SAI revocation of `CreateGroup` commits before a Group reservation commits, that reservation cannot commit as authorized. Conversely, every successful reservation must have a linearization point at which valid consent and provider registration/approval hold. An in-flight revocation must not be allowed to finish before a conflicting reservation without a deterministic, persisted order. No eventual-consistency cache, read-before-write/read-after-write check, revision stamp *in a different store*, or process-local mutex alone proves this.

PR #117 does not meet this invariant. Its pre/post consent checks correctly fail closed at request boundaries, but they cannot undo an intervening Fuseki insert. The HTTP route must remain **off**; an inactive private reservation is still a write, and an accidental later provisioning worker must never interpret an unfenced reservation as authorized.

## Observed code paths (PR #117)

- `pod-provider/backend/services/sai/access-authorizations.js`: `generateFromAccessNeedGroups` replaces/deletes authorizations; `post` and `delete` hooks update the authorization registry, special-right handling and matching access grants; `deleteOrphans` also deletes authorizations.
- `pod-provider/backend/services/sai/access-grants.js`: derived `AccessGrant` resources, not an independent consent authority. A grant's existence must never override revoked `AccessAuthorization`.
- `pod-provider/backend/services/sai/auth-registry.js`: index/reference management, not a serialized consent ledger.
- `pod-provider/backend/services/utils/collective-access-policy.js`: validates provider app allowlist, local account, app registration, and current SAI special rights.
- `pod-provider/backend/services/collective-reservations.service.js`: transactionally conditional Fuseki reservation and post-write consent check, but SAI consent reads and the settings dataset write are independent.
- `pod-provider/backend/services/collective-reservations-api.service.js`: Solid-OIDC-facing route gated by `PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED` and `PROVIDER_COLLECTIVES_API_ENABLED`.

This inventory is based on direct source inspection; **other mutation surfaces must still be enumerated** before the gate can be claimed complete. In particular inspect generic LDP delete/post, authorization registry patching, registration removal/disable, account disable/deletion, migrations, admin actions, and any direct RDF/SPARQL writes. It is insufficient to instrument only the consent UI.

## Preferred architecture: provider-owned serialized authority

1. Establish a **single provider-owned authorization ledger** with a durable revision/fencing value per `(podOwner, appUri, right)` (or a deliberately coarser scope). All revocation and grant mutations affecting `CreateGroup` must go through the same serialization boundary as Group reservations. Choose a transaction primitive proven on the deployed Fuseki/TDB2 settings dataset, *or* move both the relevant authority record and reservation write into one existing transactional database. Merely reading the SAI authorization from another dataset inside a settings-dataset transaction does not provide atomicity.
2. Persist a normalized consent projection (including explicit active/revoked status and monotonically advancing revision), with provenance to the actual SAI `AccessAuthorization` and current app registration. Treat the projection as operational authorization **only after** bootstrapping and reconciling it against SAI source-of-truth, with a no-gap mutation bridge. Missing, invalid, unreconciled or stale projection must deny.
3. On mutation, obtain the same transaction/fence, update the revision and effective right, then commit. On reservation, obtain that transaction/fence, verify active right plus current account/app eligibility, then conditionally insert the reservation in that same atomic commit. Recheck sensitive identities at the boundary; neither the HTTP request nor sidecar can provide a trusted permission snapshot.
4. If a native cross-store transaction is not available, use a **durable intent/outbox and explicit reconciliation state machine** with a hard fail-closed provisioning gate. Prove a concrete linearization order and crash recovery, including revocation while the worker runs. Do not describe this as atomic until verified.
5. Every reservation must record its authorization decision metadata: subject, app, capability, consent revision and transaction epoch; provisioning workers must validate the same authority before creating keys, actors, DID identities or federation effects. Keep the current worker lease and worker-only grant boundary independent from app consent.

## Mutation-surface closure checklist

- Authorization create, delete, replacement, orphan cleanup and any import/migration path.
- Group special-right grants and revocations through every frontend and API flow.
- App unregister, disable, ownership/identifier change, and provider allowlist removal.
- User disable/suspend/delete and account-to-WebID identity changes.
- Direct write bypasses: generic LDP routes, admin tools, background jobs, RDF writes, schema migration and repair.
- Failure halfway through registry synchronization, mirrored `AccessGrant` maintenance, or denied ACL updates.
- Reconciliation after process crash, broker retry, duplicate delivery, or provider restart.

## Tests required before enablement

1. Real Fuseki/TDB2 concurrent interleaving, using barriers rather than timing sleeps: grant/revoke/regrant vs two identical and conflicting idempotent reservations.
2. For every mutation path above, assert one durable revision/epoch change and no bypass; write-failure injection must not silently leave a granted effective state.
3. Kill/restart at each state transition; replay retries; verify monotonic revisions, idempotency, and absence of orphan *activatable* records.
4. Cross-process concurrency (not only mocked Moleculer calls); verify read-after-restart and authoritative rollback behavior.
5. Solid-OIDC HTTP integration against a deployed test provider: correct `azp`, `webid`, issuer/audience and registration checks; no client-provided headers or meta can substitute for verified identity.
6. SAI consent E2E: grant, read, revoke, concurrent revoke, app unregister and account suspension. Prove private Pod ACLs are unchanged by group-only rights.
7. Worker transition: a reservation with revoked/unreconciled authorization must never publish AP actor, signing key or ATProto DID, even after restart.
8. Full existing CI, SAI/ACL isolation suite, G1 reservation suites and real Fuseki proof must remain green.

## Execution order

**G1a** — Enumerate/close all existing mutation paths and choose the transaction/serialization primitive; prove it in an isolated integration harness.  
**G1b** — Implement authoritative revision/fence and audit trail with fail-closed migration/reconciliation.  
**G1c** — Wire reservation and worker paths through that fence; exercise concurrent revoke/commit and crashes.  
**G1d** — Validate deployed-provider Solid-OIDC + SAI consent HTTP E2E.  
**G2** — Only then implement Group actor identity, signing-key custody and ATProto DID provisioning behind worker/federation gates, with Fedify interoperability.

## Release gate

Keep both `PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED` and `PROVIDER_COLLECTIVES_API_ENABLED` false in production until G1a–G1d pass and are reviewed. Do not merge or mark PR #117 release-ready solely on mocked permissions, post-write rechecks or green CI.

## G1a progress — 2026-11-09

- Added `backend/scripts/proof-collective-consent-fence.js`: real TDB2 **synthetic** same-settings-dataset serialization demonstration for ordered revoke/reserve, concurrent requests, and restart durability. Connected it to `.github/workflows/collectives-g1-fuseki.yml`; backend syntax check includes the new script.
- This proves only that a single-dataset conditional-update primitive can be exercised. It **does not** establish the complete SAI-to-authoritative-ledger mutation bridge, close generic mutation bypasses, or validate crash recovery at every migration transition. Neither the Group HTTP route nor provisioning is authorized to launch on this basis.
- The next implementation must close `access-authorizations.generateFromAccessNeedGroups` (including replacement and orphan deletion), `access-authorizations` direct post/delete, and `app-registrations` removal, then account/provider revocations. There must be no two-store authorization gap during bootstrap/reconciliation.

### Revision-replay regression (2026-11-09)

The isolated TDB2 proof now explicitly checks a consent transition `granted@1 → revoked@2 → granted@3`: a stale request bound to revision 1 is denied, while a genuinely fresh request bound to revision 3 may commit. Both the authorized result and monotonic revision must survive database restart. These are **synthetic consent rows**, not live SAI registrations, and the production authorization bridge is still blocked.

## G1b implementation status — 2026-11-09

Implemented on PR #117 (subject to final CI):

- Provider settings-dataset consent ledger with deterministic per-(WebID, application, CreateGroup) identity, monotonically advancing revision, and durable per-mutation pending markers.
- SAI AccessAuthorization post/delete and ApplicationRegistration put/delete pre-hooks block before native LDP writes; post-hooks finish only after related registry, grant, and cache updates. Failed post-hooks deliberately leave pending markers blocked.
- Same-dataset reservation INSERT condition now requires stable status, no pending writes, and captures the matching revision. Worker transitions require the stored and live consent revisions to match, and recheck SAI.
- Real Fuseki integration proof exercises overlapping begin/finish, blocked reservation rejection, revision-bound reservations, and restart durability; SAI/account inputs in the proof are fixtures, not deployed-provider evidence.
- A code-level release fuse (CONSENT_BRIDGE_RELEASED=false) prevents environment variables alone from enabling the incomplete production flow.

### Remaining production release blockers

1. Enumerate and close every generic LDP/direct triplestore/migration bypass, including account disable, suspension, deletion, and provider allowlist changes. The upstream SemApps auth.account mutation implementation is not yet instrumented.
2. Implement fail-closed initial bootstrap of existing SAI authorizations to stable revisions, without any untracked mutation interval.
3. Build a privileged recovery mechanism for stranded pending markers with proof that no prior mutation is still running, plus bounded completed-token retention.
4. Validate native Solid-OIDC + SAI end-to-end against a deployed provider and prove the pre/post hooks are invoked for every mutation entry point, including raw HTTP/LDP operations.
5. Verify revocation versus worker provisioning, process crashes, and all ACTUAL AP signing-key/DID/federation side effects.
6. Require final-head CI, live-provider tests, and release review before lifting the code-level fuse.

The new work does not establish a complete production authorization bridge. Keep the public route, the worker lease service, and reservation operations disabled until all items above are verified.

## Review and operations update — 2026-11-09

### Resolved in the code (with isolated integration evidence)

- SAI AccessAuthorization POST/DELETE plus app registration POST/PUT/DELETE each acquire and finish a durable mutation barrier. Registration PUT refuses owner/app identity retargeting. Authorization replacement and orphan cleanup call the same underlying controlled authorization DELETE/POST actions.
- For a registered LDP container, the SemApps 1.1.4 LDP API dispatches to registry controlled actions, and ControlledContainerMixin binds the container's post/put/delete to that service. The lower-level ldp.resource actions bypass those hooks and must remain a trusted internal provider-only surface; the broker is not an authorization boundary for third-party clients. Source: https://github.com/assemblee-virtuelle/semapps/blob/middleware-v1.1.4/src/middleware/packages/ldp/mixins/controlled-container.js and its ldp/services/api/actions handlers.
- SemApps 1.1.4 auth.account uses TripleStoreAdapter(type=AuthAccount,dataset=settings) with ontology http://semapps.org/ns/core#. The reservation insert and worker transition use same-dataset existence/non-tombstone/non-disabled checks; auth.account.findByWebId independently rejects deletedAt. Tested with a real TDB2 account tombstone fixture. Source: https://github.com/assemblee-virtuelle/semapps/blob/middleware-v1.1.4/src/middleware/packages/auth/services/account.js and triplestore/adapter.js.
- Operator-signed bootstrap can initialize a virgin authorization ledger after existing SAI grants, account eligibility and registration are confirmed. It cannot overwrite an existing revision or clear pending/revocation state; real TDB2 proof covers initial bootstrap and denial of replay after a revision change.
- Offline, operator-only crash recovery exists in backend/scripts/recover-collective-consent-offline.js. Its compare-and-swap uses RDF integer revisions, invalidates pending mutation tokens and **keeps status blocked**. The old token cannot complete afterwards; the user must make a new SAI consent change. The recovery script is not an HTTP endpoint or broker service.

### Mandatory offline recovery procedure

1. Keep the G1 release fuse closed and disable both public Group route and worker activity. Stop **all** Pod-provider replicas and all other writers of SAI authorization data, not just the API gateway. Keep Fuseki running.
2. Take a verified backup of the settings dataset and the affected Pod's authorization data, document the incident and identify the exact owner WebID and registered app URI.
3. Inspect the fenced ledger with `node backend/scripts/recover-collective-consent-offline.js inspect WEBID APP`. Review the revision, blocked status and pending token count; investigate any unexpected values.
4. With `COLLECTIVES_OFFLINE_MAINTENANCE_CONFIRMED=ALL_PROVIDER_WRITERS_STOPPED` and the Group feature flags off, execute `node backend/scripts/recover-collective-consent-offline.js apply WEBID APP REVISION`. The command rejects stale revisions, missing pending markers and any attempt to reauthorize.
5. Verify revision increment and blocked status; restart the provider with the Group release fuse still closed; require a fresh native SAI consent mutation before any later review of Group creation eligibility.
6. Retain the audit trail and backup; never automate pending-marker expiry or cleanup merely by elapsed time.

### Review readiness is not release readiness

A PR may be ready for **human code review** with the immutable `CONSENT_BRIDGE_RELEASED=false` gate, disabled public endpoint and explicit open integration requirements. It is not approved for merge as a production Group feature, and it must not enable public Group creation or worker side effects. The G1 implementation still requires a deployed-provider real Solid-OIDC + SAI consent ceremony, actual HTTP route and LDP bypass tests, process restart and federation/identity side-effect proofs, and operator confirmation of rollout topology and access controls. These are not satisfied by synthetic test fixtures alone.

Future provider-side policy changes (including app disapproval) require an explicitly sequenced deployment protocol; the service allowlist is loaded from environment at process start, so overlapping old/new replicas must not be treated as an atomic policy update. Until that protocol is tested, leave the code release fuse closed.
