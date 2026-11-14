# ActivityPods: separately restricted PostgreSQL projection worker

**Status: nonactivated candidate and test. Source-controlled production signup,
PDS and native protected Jena storage release guards remain closed.**

## Why this boundary exists

The previously accepted signed-repository worker can append cryptographically
verifiable blocks and native events and advance its PostgreSQL head, but it
cannot mark an RDF projection applied. The existing
`createRdfProjectionRecovery` can independently verify a signed CAR, check
the precise canonical DID/account, run a protected Jena generation-CAS and
verify RDF readback; its SQL path was still using a general privileged
credential that could UPDATE `rdf_projection_jobs` directly.

This gate introduces a *different* PostgreSQL NOLOGIN role,
`paper_atproto_projection_worker`. It inherits only canonical SAI **read**
privileges and cannot import identities, revoke or regrant consent, sign or
mutate repository records, edit outbox delivery state or modify the underlying
projection table. It does not become a second identity or signing authority.

## Narrow PostgreSQL operations

An additive disposable migration installs four functions with
`SECURITY DEFINER`, fully qualified tables, a pinned
`pg_catalog,pg_temp` search path, and PUBLIC EXECUTE revoked within the
same migration transaction:

- `claim_verified_projection`: one indexed lease claim for exactly one
  account and DID, requiring matching live canonical identity, app, grant
  and revision. Only pending/due or expired leased work can be claimed.
  The function increments the monotone lease epoch with a bounded
  1–300 second lease and 1–20 attempt budget.
- `ack_verified_projection`: one exact owner/epoch/head/root/revision/
  generation conditional transition from **leased** to **applied**.
  Requires the currently signed PostgreSQL repository head to match and
  current canonical consent to remain active. A stale replica, revoked
  grant or expired lease cannot acknowledge.
- `release_failed_projection`: only the current lease owner/epoch can
  schedule a bounded retry or terminal block. It cannot set applied.
- `block_exhausted_projection`: only pending or expired leased work at
  its attempt ceiling can be marked blocked.

No PostgreSQL locks are held while the worker performs network I/O to
Jena/Fuseki. SQL operations are atomic, bounded, indexed and fail closed.

`assertRestrictedProjectionWorkerLogin` checks *actual* PostgreSQL 18
effective privileges, including NOINHERIT/SET ROLE escalation, schema
ownership, signer/importer/revoker membership and direct DML rights.
A general Moleculer, admin or database owner credential cannot pass.

The existing recovery state machine gains an optional
`restrictedOperations` interface which invokes exactly these SQL
functions. The previous fixture path remains intact for regression
coverage. The adapter refuses production and requires explicit disposable
markers, and no service is registered in the production loader.

## Critical release distinction: PostgreSQL is not Jena

Even exact lease and consent checks in PostgreSQL **cannot cryptographically
prove what was written to a remote Jena dataset**. The candidate's trusted
recovery callback still MUST perform the protected Jena monotone generation
CAS, read back the precise committed RDF terms, compare the signed
repository and current authorization, and only then call the SQL ACK.

A compromised projection-worker credential with EXECUTE on the ACK
function could falsely claim completion if it bypassed that trusted
readback. **This PR does not solve that threat on its own.** The remaining
production boundary requires independent, storage-level restrictions so
ordinary privileged SPARQL writers cannot mutate the protected binding,
plus a provider-controlled, independently attested Jena readback/ACK
mechanism. Until that proof exists, `NATIVE_PROTECTED_STORAGE_RELEASED`
remains `false` and production registration cannot open.

## Real disposable evidence and cleanup

PostgreSQL 18 CI provisions independent login users for projection,
signed-repository writing, generic application access and revocation.
It verifies actual catalog grants; proves that the projection worker
cannot mutate signed heads, create blocks, change grants, assume another
role or directly UPDATE the projection table; and exercises a genuine
cryptographically signed ATProto genesis, competing lease claims, stale
epoch/refuted head refusal, current lease ACK after trusted simulated
readback, and denial after canonical consent revocation.

The persisted Jena/TDB2 tests run separately and continue to prove
actual conditional RDF projection and crash/restart recovery. The new
PG18 role test uses a deterministic **test RDF callback**, not real
Jena; these two acceptances must not be misrepresented as a deployed
end-to-end security proof. The test removes roles and disposable schema.

## Remaining release requirements

- Reviewed deployable PostgreSQL migrations and distinct low-privilege
  logins/secrets for account importer, signer, canonical consent,
  projection worker, outbox dispatcher and backups.
- Protected Jena RDF write isolation from general privileged SPARQL
  clients, including independent credential and dataset boundaries.
- Actual provider-owned runtime composition for signer, PDS OAuth/DPoP,
  Solid-OIDC/SAI, canonical PostgreSQL, Jena and durable events.
- Independent Jena attestation before PG ACK, adversarial direct-SPARQL
  attempts, revocation races and node death between Jena and PG.
- Full PDS client APIs, event replay/receipts, multiple replicas,
  production-equivalent recovery and p95/p99/RSS/cost acceptance.
- Historical drafts #134/#140 reconciliation; existing-account migration
  remains out of scope.

References: PostgreSQL 18 `GRANT`, `CREATE FUNCTION`,
`SELECT ... FOR SHARE` and `pg_has_role` documentation.
