# ActivityPods signed-repository PostgreSQL 18 writer isolation

**Status: NON-ACTIVATED PostgreSQL 18 candidate. No public PDS writer,
new-account production signup, or protected Solid/Jena release.**

## Authority boundaries

ActivityPods remains the **only** WebID / ActivityPub actor /
managed `did:plc` authority and only signer of its own ATProto
repository. The PostgreSQL signed repo is the canonical operational
commit and outbox ledger. Jena/Fuseki stores Solid/RDF and the
protected identity projection. Neither Redis nor Redpanda determines
signing or grant authority.

The existing `paper_atproto_authority` identity and consent tables
already have isolated reader, revoker and one-time importer roles.
This gate creates an independent **NOLOGIN** role
`paper_atproto_repo_writer` for the signed-repository mutation path.
The repo writer inherits only the canonical authority's read-only
role. It has no authority to import/regrant consent, run the revocation
function, create a repository genesis, or overwrite protected RDF.

## Database privileges and correctness

The additive disposable
`pg-restricted-writer-roles.sql` migration is run **after**
`schema.sql`, `single-record-mutation.sql` and
`paper-atproto-canonical-authority-v1.sql`. It is not a production
migration. It grants the signed writer:

- Read access to exact signed heads, immutable CID blocks, mutation
  history, native event outbox, RDF projection intent and canonical
  identity/consent.
- INSERT of immutable changed blocks, append-only mutation records
  and pending native events. UPDATE of repository head/root/revision/
  generation only. It cannot INSERT new repository identities.
- UPDATE of the projection's **housekeeping timestamp only** so that
  PostgreSQL permits `SELECT ... FOR UPDATE` on the job. It cannot
  directly change projected head, generation, lease, status,
  `applied_at`, or evidence.
- EXECUTE of exactly one carefully restricted SECURITY DEFINER
  `reset_after_signed_commit` function, which moves an **applied**
  preceding generation to **pending** only when the new PG head,
  durable pending outbox and immutable mutation history all match.
  A duplicate or stale replay returns no row and does nothing.

The definer has a trusted `search_path=pg_catalog,pg_temp` and fully
qualified table references. PUBLIC function execution is revoked in
the **same transaction** as function creation; only the signed-writer
role receives execute. The caller cannot set projection state to
`applied`, acknowledge Kafka publication, modify consent, or bypass
the signed-head compare-and-swap. A separately reviewed projection
worker must prove Jena's monotone CAS and mark PostgreSQL applied.

The writer's existing PG transaction still locks the exact repository
and RDF projection job, checks current canonical consent with
`FOR SHARE`, writes changed blocks + signed commit + native outbox
atomically, and calls the guarded definer **before COMMIT**. No
network call takes place while PG locks are held, and uncertain
COMMIT outcomes are never blindly retried.

## Startup role admission

`assertRestrictedRepoWriterLogin` examines the **actual connection**
and `pg_catalog` privileges: PostgreSQL 18+, current login,
writer and canonical-reader inheritance, absent SET ROLE privilege,
no schema owner membership, no superuser/CREATEROLE/BYPASSRLS,
required signed-write INSERT and per-column UPDATE rights, and
prohibited projection applied/outbox ACK/identity importer and
revoker privileges. If the role is overprivileged or missing
privileges, startup must refuse it, not fall back to a general
Moleculer or migration-owner credential.

A production grant must use a distinct least-privileged LOGIN,
`GRANT paper_atproto_repo_writer TO <writer-login> WITH INHERIT TRUE,
SET FALSE, ADMIN FALSE`, an operator-managed secret and a small
bounded connection pool. Ordinary LDP/SPARQL and Fuseki credentials
receive **no PostgreSQL repository or canonical identity rights**.
Do not use the PostgreSQL owner, superuser or importer for the
runtime writer.

## Real disposable PG18 acceptance

CI creates isolated login roles (signed writer, generic reader with
zero grants, and revoker), independently authenticates each, runs
the `pg_catalog` startup admission, and checks SQLSTATE 42501 for
credential privilege escalation. The normal app cannot read signed
repo or canonical consent; the signed writer cannot import identity,
update/regrant consent, revoke, set another trusted role, acknowledge
outbox delivery, change immutable blocks, create new repo genesis, or
forge `applied` RDF state.

The test bootstraps one real secp256k1-signed repository using the
existing genesis authority, grants consent in canonical PG, then
signs an actual record with independently pinned upstream
`@atproto/repo` MST via the restricted writer LOGIN and guarded
pending transition. It checks signed CID/readback, outbox and
projection status, duplicate transition rejection, revocation with
an independent revoker login, prevention of further writes and zero
idle SQL transactions. Synthetic schemas/roles are destroyed.

## Remaining production gates

This does not activate a signed writer in the production service
loader, and the existing unrestricted fixture path remains separately
tested for compatibility. Before production use:

1. Provision reviewed **deployable** PG schema and restricted
   credentials via migrations with backup/PITR and rollback gates.
2. Fully integrate the actual provider-owned signer, PDS XRPC
   OAuth/DPoP, account and consent authority, and signed writer
   under one authentic, non-public service composition.
3. Prove the protected per-Pod Jena generation-CAS and its separate
   PostgreSQL projection-worker credential. The general privileged
   SPARQL writer isolation issue must be closed at the storage layer.
4. Integrate durable event publisher/receipt/replay and complete
   PDS authentication, Lexicons and blob endpoints.
5. Repeat multi-replica failover, simultaneous revocation, unknown
   commits, background job fencing, restore, p95/p99, RSS, queue growth
   and actual operating-cost benchmarks on the *deployed* path.
6. Reconcile historical signup drafts #134/#140 with the merged
   ActivityPods account authority; no legacy account migration yet.

The source-controlled `NATIVE_PROTECTED_STORAGE_RELEASED=false`
and signup API production guards must remain closed until independent
integration/security review accepts all release requirements.

Primary PostgreSQL 18 documentation:
- https://www.postgresql.org/docs/18/ddl-priv.html
- https://www.postgresql.org/docs/18/role-membership.html
- https://www.postgresql.org/docs/18/sql-createfunction.html
