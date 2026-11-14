# ActivityPods canonical PostgreSQL consent authority — master integration

**Status: NON-ACTIVATED; production signup and native storage release fuses CLOSED.**
This forward-port selectively recovers the canonical PostgreSQL authority and
SQL privilege-isolation work from historical stacked PR #152 onto `master`.
A PR merged into a non-default feature branch is not evidence of a production
feature. No existing account migration, import, backfill, or cutover is enabled.

## Authority and failure model

- ActivityPods owns new-account WebID = ActivityPub actor identity, managed
  DID/PLC, signing-key custody, and its PDS lifecycle. An internal UUID is a
  database key, never an additional social identity.
- PostgreSQL holds separately privileged canonical managed-identity and
  application-consent decisions. Jena remains the Solid/RDF projection and
  must not be accepted as authoritative permission evidence when canonical
  PostgreSQL mode is selected.
- Schema owner/importer, read-only and revocation credentials have distinct
  roles. A general SemApps/Fuseki writer has no canonical PG schema/table
  privileges. The runtime revoker may only invoke one SECURITY DEFINER
  conditional function, blocking the exact app grant at one expected epoch.
- The scoped runtime PG adapter uses one bounded pool per process, checks
  actual PostgreSQL login capabilities at startup, and refuses administrative
  privileges, arbitrary host DSNs, non-inherited membership in the importer
  or schema-owner role (which could allow SET ROLE), or non-disposable
  production execution.
- Both SAI mutation enforcement and signed-repository projection ticket
  issuance require current PostgreSQL consent in canonical mode. No Redis or
  SPARQL fallback is permitted on a PG outage. Unrelated Solid permissions
  continue on their existing path.

## Acceptance run on disposable infrastructure

- Backend unit tests reject mismatched owners, DIDs, app grants and revisions,
  missing permissions, SQL errors and inappropriate privileged credentials;
  exercise concurrent singleton pool initialization and safe shutdown.
- PostgreSQL 18 uses independently authenticated generic writer, reader and
  two revokers, proving 9 distinct unauthorized SQL/role operations fail.
  Two independent revokers compete: exactly one may advance the consent.
- A privileged writer successfully inserts a synthetic forged active RDF
  claim into actual Fuseki/TDB2, while the canonical PG consent remains
  blocked. The test deletes its own synthetic RDF triple and disposable PG
  roles/schema afterward.
- Ticket-issuer tests prove current signed repository verification and SAI
  evidence cannot bypass missing or denied canonical PG permission.
- No production DB, keys, account, or legacy identity is modified.

## Release blockers

The production release fuse `NATIVE_PROTECTED_STORAGE_RELEASED=false`
and production new-account guards remain unchanged. SQL role separation
is necessary but not sufficient for signup readiness. Before activating,
register a single ActivityPods-owned new-account writer and bounded real PG
pool; define a trusted initial identity/SAI grant insert protocol with
verified owner authorization and no implicit import; complete the protected
RDF generation/consent CAS and cross-store crash/restart reconciliation;
prove real hosted PDS XRPC, signed nonempty record mutations, native Redpanda
event outbox, multi-replica revocation, backups/restores and observed
performance/cost. An acknowledged PG revoke must fence all future signing
and durable publication, including previously issued tickets, across
replica and network failures.

No supported operation in this PR turns an evidence-only PostgreSQL
signup journal into `ready`. Existing-account migration is a separate,
consent-bound project outside this gate.
