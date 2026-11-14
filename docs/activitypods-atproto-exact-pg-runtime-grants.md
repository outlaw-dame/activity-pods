# Paper: exact PostgreSQL 18 runtime privilege inventory

**NONACTIVATED hardening. No production signup, public PDS registration,
protected Jena storage release or existing-account migration.**

The earlier signed-repository and projection-worker gates introduced two
independent least-privileged PostgreSQL role types. A credential admission
check that only searches for known dangerous privileges can miss a newly
granted column-level UPDATE, an unexpected table DELETE/TRUNCATE, or a
non-inherited role that can be reached through SET ROLE.

`pg-exact-runtime-privileges.mjs` is a shared **startup-only**
`pg_catalog` audit for both roles. It examines exactly the seven
canonical authority and signed-repository tables; it performs no
account-wide or per-Pod scans and does not open a new DB connection.
The probe checks the **effective** privileges of the actual authenticated
LOGIN, not environment claims about the intended role.

The projection worker has **zero** column INSERT or UPDATE permissions.
The signer is allowed only its enumerated columns: repository
head/root/revision/generation UPDATE, immutable block inserts, append-only
native events and record mutation inserts, and projection
`updated_at` UPDATE used for the PostgreSQL lease lock. Any other
INSERT/UPDATE column permission fails admission; full-table INSERT
or UPDATE is never an acceptable substitute.

For **both** logins, any table DELETE, TRUNCATE, TRIGGER, REFERENCES,
SELECT **WITH GRANT OPTION**, unexpected direct role membership, or
authority schema CREATE permission fails startup. Both prior role-specific
checks remain in force: no superuser/CREATEROLE/BYPASSRLS, signer cannot
revoke/regrant or apply RDF, projection worker cannot sign/ack native
events or impersonate the canonical importer.

## Adversarial real PostgreSQL 18 acceptance

The two existing independent-login suites now temporarily grant
forbidden privileges to otherwise accepted credentials and call
**their actual startup admissions**. Examples include projection
`UPDATE(state)`, signed-writer
`UPDATE(lease_until)`, outbox `INSERT(delivered_at)`,
block `DELETE` and `TRUNCATE`, canonical
`UPDATE(revision)`, and an unexpected NOINHERIT membership with
`SET TRUE`. Each modification must cause an explicit admission
failure; after revocation of the extra grant, the original approved
login must succeed again. The suites still independently sign
real secp256k1 ATProto commits, enforce canonical PG consent,
recover fenced projection leases and prove no duplicate commit.

The exact-role inventory is not a substitute for network-level
database credential isolation, secret rotation, database backups/PITR,
production migration review, or signed proof of remote Jena RDF state.
Do not use SQL role success to open registration.

## Jena storage release distinction

Apache Jena Fuseki supports server, dataset and endpoint ACLs, but
its documented **graph-level Data Access Control is read-only**:
it is not a write isolation mechanism for protected triples inside
the same mutable per-Pod dataset. A general administrative SPARQL
credential with update authority can still bypass application LDP
hooks. A protected dataset with separately managed service credentials
(or a reviewed write-aware storage authorization plugin), plus
independently verified Jena readback, is required before the
source-controlled `NATIVE_PROTECTED_STORAGE_RELEASED=false` can
be considered for a reviewed change.

Authoritative references:
- https://www.postgresql.org/docs/18/functions-info.html
- https://www.postgresql.org/docs/18/role-membership.html
- https://jena.apache.org/documentation/fuseki2/fuseki-data-access-control.html
- https://jena.apache.org/documentation/fuseki2/fuseki-security.html
