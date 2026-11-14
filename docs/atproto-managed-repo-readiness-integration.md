# Managed ATProto repository — new unified-account provisioning gate

**Status: MERGEABLE HARDENING ONLY; NOT PRODUCTION ACTIVATION.**

The canonical, newly created Paper account is ActivityPods-owned. It binds one
WebID (also the ActivityPub actor URI) to a locally managed `did:plc`, handle,
protected commit/rotation key references, and its PDS origin. The internal
PostgreSQL account UUID is not an additional public identity.

## Source of truth

- SemApps/Solid auth and protected ActivityPods WebID/identity bindings
  establish the account, hosting, ActivityPub actor, DID and current key refs.
  General RDF writes are **not** a substitute for a protected CAS authority.
- Provider-scoped PostgreSQL holds signed repository commits/CIDs/MST blocks,
  bounded generation history, native outbox, and recovery intents.
- `atproto-signed-repo-proof/provider-authority.mjs` obtains the actual
  protected identity binding, validates current handle resolution and PLC
  DID document, derives the commit verification key from trusted signing
  actions, and verifies the durable CAR. No external client chooses an actor,
  signer, DID document, or provider signing key.
- `provider-moleculer.mjs` is **not** registered for production. It requires a
  provider-minted, one-purpose capability, and an internal
  `atproto-provisioning` caller. Its outgoing signing RPC uses a clean
  broker metadata context rather than forwarding the capability.

## Integrated candidate flow

1. Normal new-account signup reserves its exact account and idempotency
   operation; neither the app API nor provider issues another independent PLC
   genesis as a retry.
2. With the explicit disposable test flags, `atproto-provisioning` invokes
   `atproto-managed-repository.bootstrapAndVerify`. The test-only provider
   capability is attached **only** to this one internal action. There is no
   public endpoint for repository bootstrap.
3. The provider bridge verifies current identity, PLC key, signed CAR/MST,
   PostgreSQL outbox and persistent repo head. It returns a small sanitized
   proof; no CAR bytes, signing material or arbitrary caller fields are copied.
4. The nonproduction integration fixture projects root CID/revision to the
   existing identity binding; `verifyProvisionedState` calls
   `atproto-managed-repository.verifyReady` again and requires exact
   WebID/AP/DID, protected PDS origin, root CID and revision agreement.
5. The real PostgreSQL 18 signed-repository workflow tests this path through
   the Moleculer schema and actual persisted signed genesis. The dependency-
   free action test verifies missing capability, wrong proof, unknown head,
   trusted action name, no duplicate signup and production fail-closed policy.

This is a **test seam**, not a production approval. The old
`identitybindings.upsertRepoBootstrap` write is used only by the disposable
fixture. **Production must use a provider-owned fenced per-Pod RDF CAS** which
atomically persists generation and consent revision with CID/revision and
rejects stale workers. The candidate PostgreSQL projection/recovery work
already models this, but production credentials/roles and operational
execution require distinct acceptance.

### Absolute release fuse

- `auth.signup` and `unified-account-api.create` reject all new production
  signups before any WebID, account name, key or PLC side effects while the
  end-to-end release is unfinished.
- The provider-repository schema rejects `NODE_ENV=production`. Setting
  `APODS_ATPROTO_REQUIRE_VERIFIED_REPO=true`, declaring a capability, or
  importing the candidate cannot bypass that.
- A real signed genesis is necessary but does **not** prove full PDS
  functionality, external reachability, owner authorization, native event
  delivery, or atomic production-account completion.

## Outstanding release acceptance (blocking)

1. Replace the two legacy signup entrypoint release fuses only after a single
   reviewed, authoritative ActivityPods new-signup writer is registered with
   a bounded PostgreSQL pool, least-privilege roles, approved-app and
   email-verification authority, and durable idempotent reconciliation.
2. Replace the fixture binding upsert with the protected per-Pod generation
   and SAI consent CAS; prove real SQL roles block bypassing canonical state
   through general SPARQL/Fuseki writers.
3. Prove revocation/regrant fences cannot race a read-only proof or revive a
   stale writer, including four workers, process kill, DB restart and
   transaction-commit uncertainty. Do not report ready while only
   `evidence_sealed` exists.
4. Expose working authenticated PDS XRPC, sync.getRepo/getLatestCommit,
   record writes/deletes, PLC resolution and public firehose replay from the
   PostgreSQL-signed outbox, with independent reference implementation
   verification and per-DID monotonic revision behavior.
5. Verify live HTTPS authorization/PKCE/DPoP/SAI, relocation/recovery,
   Redpanda/Redis outages, ACLs, resource budgets, load/backups/restore,
   host-level network isolation, rollback and deployment config.
6. Obtain exact-head CI and independent security review for the integrated
   activation proposal. The production release remains **NO-GO** until then.

Existing accounts are not migrated, linked, adopted or re-keyed by this work.
This document supersedes neither the main architecture baseline nor the
cross-repository authority-convergence contract.
