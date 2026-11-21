# ActivityPods — native SAI / canonical PostgreSQL owner-consent activation

**Status:** Integration candidate only. The production signup fuse, protected
storage release and hosted PDS activation remain **CLOSED**.

## Authority and operation lifecycle

A new ActivityPods-managed owner controls one WebID/ActivityPub identity and a
provider-managed ATProto DID/repository. This work does not migrate or import
existing accounts. The canonical grant decision is held by PostgreSQL, not by
a mutable RDF permission assertion in ordinary Fuseki.

| Canonical consent | How it is reached | Authorization |
| --- | --- | --- |
| Absent | No provider-issued owner-signup record | Deny |
| Pending, revision 1 | Restricted coordinator issues a new owner operation with a fixed SHA-256 request receipt | **Deny** repository signing, projection tickets and durable publication |
| Active, revision 1 | Separate PG attestor credential verifies native owner/registry/registration/grant/need group and mandatory rights in independently protected Jena/TDB2; exact operation and evidence CAS | Only the remaining independent PG/signed-head/SAI checks may authorize |
| Blocked, revision 2 | Owner invokes the native grant-revocation fence before or after activation | **Deny permanently** under this initial-activation protocol; cannot re-open from a stale Jena record |

There is no permissive fallback on a PostgreSQL/Jena failure. A missing or
contradictory RDF binding denies; identity, registration, grant, agent and need
group must match the exact owner, application and required special rights.
An issuer cannot mint an activation receipt; the attestor cannot mint an
initial operation; ordinary SemApps/Jena credentials cannot call either SQL
function. The restricted PG revoker has its own conditional one-way path.
All privileges remain separate from the application signup HTTP handlers.

## Explicit integration and security checks

- Additive PostgreSQL v2 candidate schema migration, owner operation ID and
  bounded digest columns, pending → active exact-once CAS, idempotent replay
  only at the same operation/evidence and revision, one-way revoke during
  either pending or active status.
- Native SAI grant POST under *existing pending coordinator authority* no
  longer revokes that specific unactivated grant. It is still bound to a
  locally authenticated Pod owner and WebACL, never an impersonating app.
  Native DELETE advances the durable PostgreSQL revocation epoch even before
  first activation.
- The attestor independently queries Jena with **read-only** credentials,
  validates typed RDF terms and all mandatory application rights, hashes a
  canonical evidence set, calls the scoped PostgreSQL attestation operation,
  reads Jena again, and confirms the same *current* PG grant before returning.
  No arbitrary SPARQL/dataset/client-selected query is accepted.
- The original independent PostgreSQL 18 test covers six separate login
  connections, direct DML denial, cross-function privilege denial, missing
  grant refusal, lost ACK replay, two independent attestors and two revoker
  race contenders. All proof credentials and rows are disposable.
- The real Jena TDB2 proof persists the pending owner and native SAI triples,
  exits its process, restarts Fuseki, admits two independent PG attestors on
  fresh Jena reads, blocks an old still-present RDF permission after revoke,
  and fails closed if the projector removes a required native SAI right.
- Unit denial matrix tests unexpected rights, extra/duplicated grants,
  contradictory owner or app, literals in place of IRIs, missing required
  rights, cap exceedance, unapproved role inheritance and revocation between
  the second Jena read and final PG confirmation.

The final PG check closes one staleness window, **but does not atomically lock
Jena and PostgreSQL**. Every repository signing operation must continue to
revalidate current canonical PG consent at the correct revision and key.

## Deliberately unfinished production dependencies

1. **Real signup coordinator binding.** The restricted issuer SQL function is
   a nonactivated candidate; its receipt must be issued exclusively from a
   committed, owner-authenticated provider signup reservation and immutable
   scope. Never call it directly from a browser, generic SAI route or
   application-supplied bearer token. Bind the pending operation ID to the
   canonical new-account journal and verify owner/DID/username/evidence.
2. **Provider-owned SAI projection and attestor service.** The live proof uses
   the isolated test Jena dataset, not an installed production projection.
   Native per-owner SAI data must be mapped to an independently protected
   dataset under a strictly scoped writer with revocation-fenced version/CAS.
   The general SPARQL writer must not have access to this dataset.
3. **Revocation and credential epochs.** Existing Paper OIDC tokens (especially
   refresh tokens and remembered sessions) must be tested for non-resurrection
   after revoke → owner-authorized new consent. A revocation must fence all
   previously issued signing and durable-publication tickets across replicas.
4. **Production key/PDS and operational readiness.** Independently hosted and
   provider-signed PDS lifecycle, real non-empty repo writes and external
   readback, lost acknowledgments, process kill and restore/write epochs,
   p95/p99 and memory measurements, backups, permission boundaries, and
   independent security review remain required.
5. **Release control.** `NATIVE_PROTECTED_STORAGE_RELEASED=false` and every
   production account-creation fuse must stay closed. The disposable PG18 and
   Fuseki tests do not authorize setting release flags or migration of
   previously existing accounts.

## Tracking and handoff

Use `outlaw-dame/activity-pods` PR #255 as the review/change tracker. CI
workflows `paper-atproto-signed-repo-proof.yml` and
`paper-atproto-fuseki-isolation-proof.yml` contain exact-head backend/PG18,
native-SAI, credential-admission and Jena restart evidence. The federation
repository's staging source lock must remain on its previously approved SHA
until PR #255 is reviewed/merged and its separate deployment acceptance is
performed. Record exact commit, dependency digests, scenario and sanitized
result; never log tokens/credentials or claim production release from a
passing fixture. No automatic retry of a potentially side-effecting native
SAI or PDS write after an ambiguous acknowledgment.
