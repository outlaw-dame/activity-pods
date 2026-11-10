# ActivityPods Account and Group Data: PostgreSQL Adoption Decision
**Status:** architecture decision / release blocked. **Date:** 2026-11-10.
**Scope:** ActivityPods Pod provider, all apps (including Paper), AP+ATProto identities, Solid-OIDC/SAI and Group control plane.

## Direct recommendation

1. **Adopt PostgreSQL as the planned sole canonical transactional store for Paper Groups** (subject to a provider-wide consent/revocation bridge, migration proof and recovery gates). Do not activate the existing isolated candidates simply because component tests pass.
2. **Evaluate PostgreSQL as the eventual canonical *authentication-account and operational-account* store** after the Group consent bridge succeeds. This is a good fit for unique account handles, verified email uniqueness, account status, tenant/provider scoping, session/authentication metadata, device records and transactional lifecycle associations. Design as one explicit owner, not a second independently writable account authority.
3. **Preserve WebID, Solid-OIDC protocol, Pod datasets/ACL, WebACL/ACP and RDF/LDP as the external identity and data interface.** PostgreSQL storage is orthogonal to WebID: a user must have the same canonical WebID when dereferenced and when used for Solid authorization. The runtime can render or maintain a read-only RDF identity projection from canonical relational account data after an explicit single-authority migration; arbitrary SPARQL updates must not mutate its primary keys/rights.
4. **Do not migrate everything at once.** Group workflow state is better bounded and measurable than replacing the existing SemApps account mixin, user provisioning, OIDC and protected linked-data services in one project. Do not use an in-memory cache/Redis TTL as an authorization boundary.
5. Keep **Fedify as the only remote ActivityPub delivery HTTP executor** and the separate APDM local Pod write path. Neither PostgreSQL nor a new Moleculer service should add a redundant remote recipient loop.

## Actual existing ActivityPods architecture and risks

The current `backend/services/core/auth.js` uses `@semapps/auth` `AuthLocalService` with `accountsDataset=SEMAPPS_AUTH_ACCOUNTS_DATASET`; during signup it calls:
- `username-moderation.assertSafe`, `dataset-provisioning.ensureSecureDataset`, `triplestore.dataset.exist`;
- `auth.account.create`, `webid.createWebId`, `auth.account.attachWebId`, `ctx.emit('auth.registered')`;
- keys readiness, `activitypub-provisioning.provisionForAccount`, optionally `atproto-provisioning.provisionForAccount`; followed by JWT issuance;
- `auth.awaitBootstrapComplete` for preferences, auth agent/registry, data registry, actor and type-index completeness in production.

Existing `backend/services/identitybindings.service.js` uses SemApps `ControlledContainerMixin` storing `AtprotoIdentityBinding` and an index with canonicalAccountId, WebID, AP actor, ATProto DID and handle, key references and repository status. Those are **separate federated identity associations**, not basic login credentials and not disposable cache entries.

The real mixed-Redis four-cell CI failure (sidecar PR #120 / issue #122) demonstrated that all requisite Moleculer services may advertise readiness while newly registered accounts are still missing `pim:preferencesFile`, `interop:hasAuthorizationAgent`, and `interop:hasRegistrySet`. **Replacing accountsDataset with PostgreSQL does not, by itself, repair this asynchronous Solid registration / distributed event lifecycle.** Resolve the producer/consumer resource-creation sequence and make signup idempotently recoverable first.

## Domain-by-domain storage placement

| Data domain | Candidate authority | Migration constraint |
|---|---|---|
| Auth account UUID, provider/tenant ID, normalized unique username, email verification, login-enabled/suspended/deleted state | PostgreSQL *after* explicit migration | Preserve existing WebID exactly; unique names within tenant; normalization rules/security review; never change password hashes silently |
| Password verifiers, WebAuthn/passkeys if an **account-wide** sign-in feature is later implemented, MFA recovery metadata | Dedicated secured auth service backed by PostgreSQL if its OIDC provider supports this integration | Strong at-rest secrets management, algorithm agility, secure hashing, no token/key material in analytics or application RPC; **do not add passkeys as Group-specific authority** |
| OAuth/Solid-OIDC client registration, sessions, tokens, consent and revocation ledger | Existing canonical Solid-OIDC provider until independently migrated; PG only with a single protocol boundary | DPoP/PKCE, actual provider callbacks, race-proof revocation, key rotation, token lifetimes, logout and account disable |
| Group membership, join requests/invites, roles/bans, revision, per-Group authorization generation | Planned PostgreSQL **single canonical Group authority** | Live SAI/owner revoke fence must be committed before any revoke acknowledgement; consent-first admission, audited intent and actor proof |
| Account ↔ Group associations, subscription settings, moderation actions, notification delivery state, idempotency receipts | PostgreSQL operational control plane if contract permits | Use one canonical writer; no duplicate member/follow graphs; retention/privacy/erasure |
| ATProto DID/handle mapping, AP actor ID/handle, local/external account linkage | Canonical protected identity-binding store until a dedicated migration; PG can eventually own relational association with a read-only RDF projection | DID rotation/recovery, unique active handle, account unbinding and proof; never manufacture dual identities from an eventual projection |
| WebID profiles, Pod RDF/LD content, Solid storage, WAC/ACP rights and application interop resources | Jena/SemApps and Solid protocol | Must remain dereferenceable, user-controllable and protocol-consistent; no unguarded SQL bypass of Pod ACL |
| Search, public display metadata, common actor descriptors and immutable snapshots | Derived indexes/materialized projections/cache | Revision/digest/visibility keyed, bounded, invalidate on source change; cannot authorize any action |
| Durable jobs/outbox, per-destination attempts and remote sidecar delivery | Existing APDM/Fedify coordinator unless a **single** migration reduces complexity | No second queue or HTTP publisher; bounded costs, retries/idempotency and per-server fairness |

## Single-authority migration protocol

**Phase A — map, measure, and test:** enumerate exact `AuthLocalService` RDF account triples, OIDC provider account stores and identity-binding writes. Record real consistency invariants (username/email uniqueness, login WebID, account lifecycle, Pod provisioned marker, consent generation). Establish a repeatable 1/2/4/8-cell mixed workload, including SIGNUP/DELETE/REVOKE/REREGISTER with flaky services. Test actual users and privacy rules only using disposable data.

**Phase B — define canonical account ID:** stable random account ID + unique provider/tenant normalized username, immutable canonical WebID URI, optional AP actor URI and ATProto DID. Validate collision resolution, username rename/redirect, deleted/recycled usernames, multiple devices, app installs, domain migration, GDPR/DSA retention and backup. WebID remains the external identifier. Credential and key material never appear in public RDF projections.

**Phase C — fix distributed provisioning:** under a durable, idempotent per-account provision state machine (reserved, auth-ready, WebID-provisioning, Pod-ready, AP-ready, AT-ready, complete, failed/recoverable), checkpoint each state and reconcile missing Solid resources. Avoid N Pod service calls per account read, and don't consider HTTP 200 or Moleculer registry availability proof that private Solid/SAI resources exist. Gate visible account readiness on actual required resources; repair on restart with bounded exponential backoff rather than constantly retrying every user operation.

**Phase D — Group PostgreSQL live authority cutover:** integrate the existing canonical Solid-OIDC/SAI **revoke** path with a durable *deny-first* SQL consent revision lock and Group writes that share the same row. A local revoke cannot return success while SQL would still permit authorized Group changes. Handle network partitions and unknown commit outcomes with a reconciliation journal and deny-by-default provisional state; use exact operation ID and monotonic grant generation. No independent dual writes. Prove SIGKILL before/after DB commit and while source TDB2 grant changes.

**Phase E — authentication accounts migration, separately:** establish a single cutover barrier with all login/write paths paused or fail-closed, export bounded sorted account batches, verify hashes/uniqueness and exact ID mapping, and compare byte-exact or canonicalized account state and WebID RDF projection. Switch the `AuthLocalService` authority via a reviewed adapter and actual OIDC integration. Old RDF account records become immutable or protected projections; never re-enable legacy create/update in parallel. Shadow READ comparisons (without sensitive record output) are okay; shadow WRITES as separate authority are not. Provide reversible *pre-commit* migration; after canonical writes resume, rollback is a new controlled migration, not a silent switch back to stale TDB2 accounts.

**Phase F — acceptance:** n=1,2,4,8 replicas; 100k users and large Groups; concurrent signup/name conflict/disable/revoke/member join, node crashes and rolling upgrades; DB restart/failover, stale OIDC tokens, backup PITR and restore, cancellation; no stale grants or duplicate identity links, no N-recipient RPC amplification, measured p95/p99, memory/disk/WAL/CPU, and monthly operating cost. No production activation until proven.

## Database efficiency and cost

- One bounded node-postgres pool per Moleculer **process**, not per account/Group. If N cells have P connections, capacity is N*P plus maintenance headroom; measure per-action queue time and SQL lock wait before increasing P. PgBouncer transaction pooling is optional and requires verifying prepared statements and session-state behavior.
- Account lookup indexes: uniquely scoped `(provider_id, normalized_username)`, partial active-email uniqueness only where policy permits, canonical WebID uniqueness, account ID primary key. Add foreign-key indexes that actual joins require; avoid dozens of speculative indexes. Retire associations instead of allowing unbounded duplicate rows.
- Favor transactional state changes and a bounded outbox over multi-call lifecycle fanout. Avoid broker round trips inside DB row locks; asynchronous steps must be idempotent, versioned and checkpointed.
- Respect consent, per-account privacy, tenant boundaries and IDOR protection in the actual service layer; use least-privileged PostgreSQL roles and evaluate RLS carefully before enabling any direct SQL API. The API must never expose an unrestricted SQL client or let callers set owner identity.
- Monitor WAL bytes, dead tuples, autovacuum, shared buffer/cache hit ratio, index bloat, I/O, pool wait, lock conflicts, DB restarts, backup retention. Do not disable fsync or relax durability to win microbenchmarks. Benchmark Zstandard/LZ4 WAL compression on the actual deployment build/CPU before enabling.
- Durable account rows with infrequent updates usually favor PostgreSQL indexes; **user-authentication account count is not automatically the high-write bottleneck**. The measured TDB2 issue occurs mainly with shared-settings concurrent writers and per-recipient amplification. Prioritize measurable improvements, not a wholesale database replacement.

## HTTP ETags / intelligent caching

Use strong `ETag` and `If-None-Match` for public, stable, exactly-versioned WebID profile representations or public Group actor descriptions **after authorization**, honoring content type and RDF serialization. Don't cache private rosters or grants. Avoid serving 304 for resources the current requester cannot read. For updates, `If-Match` must be checked in the same canonical authority operation; it cannot replace the SQL consent/group revision fence or be calculated from a stale RDF projection.

At the service boundary, bounded **per-operation memoization** of immutable pages/actor descriptors may save decoding; cache hits must be scoped by provider, resource URI, exact revision and representation digest and require current permission validation. Do not reanimate Fedify's retired hostname-derived sharedInbox cache.

## Decision for current work

- **Green:** non-activated PG candidate v1/v2, 100k roster/index proof, bounded Moleculer adapter, SQL row-lock revocation proof.
- **Red:** actual live Solid-OIDC/SAI revocation propagation, 4-cell account bootstrap, Friendica Follow persistence, multi-replica crash/recovery, sealed cross-page Fedify delivery and production cost envelope.
- Therefore keep the production release gate closed. A narrower migration can follow once the authority and recovery proof exists; no blanket switch for ActivityPods accounts yet.

Primary references:
- https://solid.github.io/specification/protocol
- https://solid.github.io/solid-oidc/
- https://solid.github.io/data-interoperability-panel/specification/
- https://jena.apache.org/documentation/tdb/tdb_transactions.html
- https://www.postgresql.org/docs/current/explicit-locking.html
- https://www.postgresql.org/docs/current/ddl-constraints.html
- https://www.postgresql.org/docs/current/indexes-partial.html
- https://www.postgresql.org/docs/current/routine-vacuuming.html
- https://node-postgres.com/features/pooling
