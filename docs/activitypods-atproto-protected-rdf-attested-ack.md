# ActivityPods: independent Jena attestation before PostgreSQL projection ACK

**Status: nonactivated integration gate. Production signup, PDS registration,
protected storage release, and legacy account migration remain disabled.**

## Security problem closed by this candidate

The merged restricted PostgreSQL projection worker could invoke
`ack_verified_projection` from its own SQL credential. A compromised worker
could therefore falsely mark RDF projection `applied` despite never reading
back the correct Jena state. A Jena HTTP 2xx response alone is *not* an
atomic-CAS success acknowledgement.

This gate moves proof of the *remote Jena contents* to an independently
credentialed **read-only RDF attestor** that has no PostgreSQL projection
claim/ACK/revocation rights and no Fuseki SPARQL Update rights.

## Concrete implementation

- Add an independent `paper_atproto_rdf_attestor` PostgreSQL 18 NOLOGIN
  role and independently authenticated LOGIN in disposable acceptance.
  Startup inspects actual membership/effective privileges, all seven
  existing restricted tables and additional receipt permissions. Unexpected
  DML, SET ROLE, signing, regrant or ACK causes immediate refusal.
- Add one bounded `rdf_attestations` receipt **per account/DID**, not one
  per event/attempt. New leases replace previous receipts only when
  `lease_epoch` strictly increases, and identical retries are idempotent.
  No orphan-lease scan or unbounded history.
- Add the `SECURITY DEFINER attest_protected_rdf` function. It requires
  the exact current signed PostgreSQL repo/head/generation, owner/DID,
  active canonical SAI grant and revision, lease owner/epoch and unexpired
  lease. The trusted attestor supplies a SHA-256 digest of *read-back,
  typed RDF terms*; SQL neither invents nor independently verifies the
  remote RDF data.
- **Revoke** the projection worker's legacy
  `ack_verified_projection` EXECUTE and replace it with
  `ack_attested_projection`, which only succeeds if the active current
  canonical grant, PG head, exact lease and a fresh matching independently
  stored receipt exist. The receipt cannot be inserted directly by
  either restricted login. Functions use explicit schemas and pinned
  `pg_catalog,pg_temp` search paths; PUBLIC EXECUTE is revoked in
  the same migration transaction.
- Introduce a separate strictly test-only protected-RDF reader. It has a
  fixed loopback Fuseki origin, protected dataset, constant RDF subject,
  exact bounded SPARQL query (16-result cap), bounded response memory
  and network deadline, no redirect-following, and a distinct read-only
  Shiro principal. It rejects missing, duplicated, contradictory, wrong-
  typed and wrong-head/fence RDF terms rather than using `LIMIT 1`.
- Wire real PG18/privilege tests to real persistent Jena TDB2 in the
  disposable isolation workflow, including actual secp256k1 signed genesis,
  competing leases, no-receipt ACK refusal, a successful independently
  attested ACK, wrong-head refusal, crash/replay stale receipt rejection,
  receipt cardinality bounds, post-attestation revocation and restart.
  The workflow creates and removes only synthetic roles and datasets.

The previous fixture-only projection/recovery tests retain their legacy
SQL behavior on their independently disposable schema. They are **not**
fallback runtime paths in the new restricted-attestation composition.

## Explicit security and production boundaries

1. This establishes a read-only Jena **credential** for an independent
   attestor, an isolated protected dataset and a SQL ACK gate; it does
   **not** yet migrate actual ActivityPods identity/SAI bindings out of
   the per-user Solid dataset. General per-Pod SPARQL write access must
   not be given to the protected dataset.
2. The legitimate projection writer can still send arbitrary SPARQL updates
   using its test-only protected-dataset writer credential. Production
   requires a narrower purpose-built provider writer endpoint/operation
   and independent dataset/network credentials; no generic SPARQL Update
   capability should leak into ordinary services. A compromised privileged
   Jena admin or trusted attestor process remains outside this threat model.
3. Postgres cannot atomically attest or lock Jena data across two stores.
   Therefore **fresh independent readback is mandatory at every readiness
   decision**, even after ACK, and recovery must detect content drift.
   This test exercises a readback after ACK and again after Jena restart,
   but has not yet integrated the production signup/readiness callsite.
4. No client supplies a dataset URI, graph or SPARQL body to the attestor;
   the disposable fixed origin/subject is deliberate. Production needs
   reviewed owner/account-to-protected-resource resolution and a trusted
   provider-held identity mapping, without creating a second WebID/DID
   authority. ActivityPods remains the sole identity/provisioning owner.
5. Deployment must use current, reviewed and digest-pinned Jena images,
   TLS and network policies, external secret management and rotation,
   deployable PG migration/backups/PITR, independent readback worker
   lifecycle, and locked-down restore/administrative credentials. The
   existing disposable `semapps/jena-fuseki-webacl` image is observed to
   run Jena 3.17.0 and is **not** thereby approved for production.
6. Before activating protected storage, run real provider-owned
   Moleculer/Solid-OIDC/SAI integration (including all grant mutation
   paths), multi-replica failure/retry admission, adversarial direct
   SPARQL and compromised projector tests, restore, p95/p99/RSS,
   queue growth and operating cost measurements, and independent review.
   Production fuses stay closed.

## Jena compatibility and security release gate (verified November 14, 2026)

The disposable Fuseki/Shiro image currently used by ActivityPods tests was
observed by CI to run **Apache Jena 3.17.0 / Java 8**. Apache's latest active
Jena release is **6.2.0** (July 2026), requiring **Java 21+**. Apache Jena
6.0 retired the old Fuseki WAR/webapp packaging and `jena-permissions`.
Jena 6.2 additionally fixes a long-running **Shiro memory leak** and a
TDB2 robustness issue following system-level errors. Consequently, simply
swapping the existing `semapps/jena-fuseki-webacl` tag for a Jena 6 image
would be an unverified and likely incompatible migration.

Before production:
- Inventory the exact `semapps/jena-fuseki-webacl` custom extension,
  web ACL enforcement, authenticated SPARQL endpoints, storage hooks and
  per-Pod dataset naming/creation semantics.
- Select a supported, reproducible Jena 6.2+ / Java 21+ deployment or
  explicitly justified maintained variant, build reproducibly and pin
  its immutable image digest after validation. Do not silently bypass
  the now-retired Jena permissions mechanism.
- Exercise compatible, **real** Solid-OIDC/SAI read/write enforcement,
  protected dataset endpoint ACLs and independent read-only attestor
  against this new image. Include fresh TDB2 migration/cold restore,
  concurrent CAS, crash consistency, data corruption detection, resource
  growth, p95/p99 and existing application regressions.
- Use operator backup/PITR and tested restoration procedures. Never
  mount an old 3.x live TDB2 data directory directly into a new major
  runtime without an accepted migration strategy.

Primary Apache sources:
- https://jena.apache.org/download/
- https://release-catalog.apache.org/jena/index.html
- https://github.com/apache/jena/blob/main/CHANGES.txt
- https://jena.apache.org/documentation/fuseki2/fuseki-data-access-control.html

## Operational invariants

- **Authority:** ActivityPods owns WebID, AP actor, DID, canonical consent.
- **Signed repository:** PostgreSQL owns immutable signed blocks and head.
- **Protected RDF:** only trusted provider writer writes protected binding;
  independently credentialed reader checks complete terms/fence.
- **ACK:** requires fresh independently stored evidence **and** active
  canonical PostgreSQL consent at the same transition.
- **Revocation:** revocation wins over a pre-existing receipt.
- **Recovery:** a superseded lease never inherits its predecessor's receipt.
- **Memory/scale:** fixed-size Jena read query and a single current receipt
  per DID; no per-Pod scans or SQL transactions across Jena I/O.

References: PostgreSQL 18 `GRANT`, role membership, `SECURITY DEFINER`;
Apache Jena Fuseki Full Security, Data Access Control, and endpoint APIs.

## Follow-on: automatic recovery and readiness composition

The existing `createRdfProjectionRecovery` state machine now recognizes an
explicit `requiresIndependentAttestation` marker from the separately
restricted PG18 SQL operations. In that mode, constructing a worker without
both an independent `attest` and `verifyReadback` function fails closed.
The following operations are enforced in sequence:

1. Claim the exact PG lease and current canonical grant; read and fence the
   protected RDF using the existing trusted writer.
2. Recheck the independently signed repo/head and authorization, then call
   the **separate** read-only Jena attestor to record a lease-bound receipt.
3. Require the attestor's matching acknowledgement metadata and recheck the
   grant and signed head before the restricted SQL ACK transition.
4. After ACK, and at **every** later readiness decision, require both the
   existing protected RDF identity readback and the independently credentialed
   attestor readback to match the applied PG generation/fence, followed by
   rechecking canonical authorization and signed head. SQL's prior receipt
   alone is never a sufficient current-readiness proof.

Real disposable PG18 + TDB2 acceptance composes these functions through the
**actual recovery state machine**, validates missing-attestor refusal,
a crash-retry after a prior receipt with a newer lease, successful automatic
re-attestation/ACK, rejection of a worker callback that lies about RDF while
the protected Fuseki dataset is tampered with, and refusal of a non-digest
response. It retains the independent after-ACK canonical revocation race,
restart verification and bounded receipt table.

This remains a nonactivated candidate and is not a production deployment:
proper per-Pod protected RDF isolation, provider-owned service registration,
active Solid-OIDC/SAI enforcement and Jena 6 compatibility/upgrade are
separate required release gates. The "no committed distributed transaction"
property remains: the next operation must re-read/revalidate state, not
assume earlier HTTP or SQL acceptance proves present Jena contents.
