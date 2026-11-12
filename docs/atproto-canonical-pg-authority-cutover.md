# Managed-ATProto PostgreSQL authority: controlled cutover gates

Status: **DRAFT, SOURCE-LOCKED, DISPOSABLE TEST MODE ONLY**.
This milestone is stacked on PR #151. The production source fuse
`NATIVE_PROTECTED_STORAGE_RELEASED=false` is unchanged.

## Security boundary

The canonical identities and app consents live in
`paper_atproto_authority.identities` and `paper_atproto_authority.consents`.
They are separate from mutable Jena/Solid RDF resources. The general
SemApps/Fuseki/SPARQL credentials have **no database role membership**,
table DML, or `block_consent` EXECUTE rights. A privileged Fuseki
`INSERT DATA` of a forged active consent is therefore incapable of
reactivating a revoked PostgreSQL consent.

A migration admin owns the PostgreSQL schema. Separate logins should be
granted only the NOLOGIN reader, revoker, or initial importer roles.
The runtime's revoker credential has SELECT and narrowly scoped EXECUTE;
it cannot directly INSERT, UPDATE, DELETE, TRUNCATE or ALTER canonical
tables, create schema objects, or become a migration administrator.
An explicit startup introspection query tests actual PostgreSQL privileges,
not claims about a connection string's username.

The only runtime revocation function performs a single conditional,
monotonic `active -> blocked` transaction against the exact owner,
app, grant and version. The owner authentication is performed earlier
in the protected SAI action. If either permission check or PostgreSQL
fails, the SAI mutation does not continue. No generic SPARQL fallback.

Signed repository projection ticket issuance now requires a real-time,
separate canonical PostgreSQL check of active identity+consent, matching
owner/DID/app/grant/revision, in addition to its existing verified signing
head and recovery lease. An RDF grant alone cannot mint a ticket.

## Account import and release procedure

The SQL includes an import-only role but **does not turn on automatic account
migration**. Before any active PostgreSQL row may be imported:

1. Freeze managed-ATProto repo grant issuance, SAI app changes, and native
   repository writes for the exact account while reconciling authority;
   ordinary Solid actions should continue independently where possible.
2. Require trusted server-verified account WebID, managed DID/PLC signature,
   current Solid-OIDC/DPoP owner approval, matching live AccessGrant and
   DataGrant, expected application, and a concrete consent revision.
   A general privileged Jena read is not proof of owner approval.
3. Import one bounded account (and its explicitly verified apps) via the
   dedicated importer login, using INSERT-only operations. Verify the
   imported record's proof fingerprint and revision. Neither blind
   `ON CONFLICT DO UPDATE` nor a full-instance scan is permitted.
4. Confirm distinct database credentials on **every** node and prove the
   generic Fuseki identity cannot read, update or execute revocation.
   Record an auditable but secret-free migration manifest. Compare the
   PG canonical state with the RDF projection and reject disagreement.
5. Recheck PG canonical permission at both ticket issuance and the actual
   fenced write boundary; test revocation races and stale tickets across
   multiple processes. A successful ticket issuance is not durable user
   permission if it becomes stale before the writer uses it.
6. Perform real enforced Solid-OIDC/SAI consent, uninstall/revoke/delete,
   redelegation and multi-node restart tests. Measure response time,
   provider PG pool saturation, request memory/RSS, tenant isolation,
   offline recovery and backup/PITR with rollback.
7. Explicitly review and change the source-controlled release fuse only
   after all gates pass. Never use disposable PostgreSQL DSNs or the
   administrative migration credentials outside that test environment.

**Rollback:** If the cutover fails, stop native repository writes and
permission issuance (fail closed). Do not restore mutable Jena RDF as
permission authority. Recover the PostgreSQL authority from an audited
backup/PITR snapshot, reconcile signed repository heads, and reverify
owner-grant state before resuming. An already blocked consent stays
blocked; do not resurrect it from an old snapshot without fresh user
approval. Independent activity publication should remain unaffected.

## Completed disposable evidence

Real PostgreSQL 18 proof tests exercise separate general, reader and
revoker logins, wrong-role denial, one-way grant revocation, two
concurrent revokers, and a privileged Jena/TDB2 write that successfully
creates a forged RDF claim but cannot change canonical PostgreSQL
consent. Native SAI mock tests confirm that a PostgreSQL outage denies
revocation rather than falling back to SPARQL. Backend tests check
pool single-flight initialization and shutdown behavior.

This is not yet the production migration or the fully protected live
writer. No production database, security flags or runtime secrets are
modified by this PR. See `docs/atproto-native-authorization-integration.md`
for the earlier security and capacity gates.
