# ATProto managed identity and consent: PostgreSQL authority cutover

This integration introduces a **separate canonical PostgreSQL 18 control
plane** for managed ATProto account identity and grant consent. Solid/Jena
continues storing RDF resources for LDP/WebID interoperability, but a
privileged generic `triplestore.update`, `insert`, direct Fuseki HTTP
write, or migration must **never** be an authority to re-activate a
managed repository grant.

## Runtime separation

The migration is `pod-provider/backend/sql/paper-atproto-canonical-authority-v1.sql`.
It creates:
- `paper_atproto_authority.identities` (one verified managed WebID→DID
  mapping plus revision and source-proof hash);
- `paper_atproto_authority.consents` (one exact owner/app/grant binding,
  monotonic revision and active/blocked state);
- `block_consent(owner,app,grant,expected_revision)`, a single
  transactional active→blocked CAS, owned by the migration administrator,
  with a restricted search path and no broad table UPDATE rights.

Only the admin migration role may mutate table definitions. The named
NOLOGIN runtime roles split SELECT, revocation EXECUTE, and one-time
verified import; actual LOGIN credentials must be provisioned separately
with network isolation and distinct secrets. The ordinary Fuseki/SPARQL
writer gets **no** role membership, schema USAGE or function EXECUTE.
The only indexed consent lookup uses its existing (owner_webid,app_uri)
primary key; no redundant secondary index or account scan is introduced.

The existing native SAI before-hook switches to `getIdentity/getConsent`
in the PG-specific mode and commits a PG revocation before completing
an owner's permission removal. It does not fall back to RDF if the PG
connection fails, and it verifies the blocked state afterward. Existing
WebACL, native SAI container membership, and authenticated-owner checks
still run. The ordinary non-PG test path remains unchanged.

The provider pool is lazy, at most two connections per SAI provider
process, and is never allocated per Pod. Network/service errors deny the
protected change rather than re-enabling a stale grant. The new source
flag `APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED` cannot be enabled
without the existing native SAI fence. The source-controlled production
release fuse remains closed; only explicit disposable test fixtures can
instantiate this authority while the migration is under review.

## Import and release prerequisites

Importers must select each existing managed account by exact owner WebID
and verify the live Solid-OIDC owner, signed ATProto DID/PLC binding,
current SAI grant, client app, provider-held keys, and signed repository
head. They may INSERT only a verified initial snapshot, never overwrite
an existing canonical row. Store only fixed-length evidence hashes and
the required authority tuple; do not copy access tokens, OAuth codes or
private keys into PostgreSQL. An account missing verified PG authority
must fail managed-repository readiness, not fall back to RDF.

**Remaining implementation gate:** The native provider uses PG for the
SAI revocation hook in its explicitly enabled mode. Production bootstraps
of existing identity bindings and a release-approved reauthorization
ceremony are not implemented here; the repository ticket/readiness paths
must use the PG reader, with a projection-consistency check against RDF,
before this can be activated. A process-local SAI parent proof also needs
a distributed, authenticated parent-action capability across Moleculer
nodes. Complete these and real sign-in/grant/uninstall/revoke flows
before changing either release fuse.

## Disposable negative acceptance

The PG18 proof tests separate ordinary, importer and revoker connections,
rejects ordinary/underprivileged DML, proves one winner in concurrent
revocations and rejects stale grants. In a real PG18 + Jena TDB2 proof,
a privileged Fuseki writer deliberately forges an active RDF consent
triple after PG revocation; PG remains blocked. That proves the storage
boundary, not yet full production permission enforcement.

The source of truth and its least-privilege credentials must remain
outside the generic Fuseki and Pod-resource mutation processes in a
production multi-service deployment.
