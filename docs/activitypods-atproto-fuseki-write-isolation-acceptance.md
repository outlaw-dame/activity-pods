# Paper / ActivityPods: isolated Fuseki write-admission acceptance

**Status: DISPOSABLE, NONACTIVATED PROOF. Production NO-GO remains.**

## What this change establishes

The merged signed-repository and projection-worker SQL roles provide independent,
least-privileged PostgreSQL 18 logins. They do *not* prevent a general-purpose
SPARQL writer with mutable access to a per-user Pod dataset from rewriting the
protected RDF binding after the PostgreSQL projection ACK.

This change introduces a **separate, disposable** Fuseki Full HTTP fixture,
not a replacement for the running ActivityPods SemApps triplestore:

- One synthetic `protected-proof` TDB2 dataset is writable and readable by
  a `projectors` principal only; a different synthetic `ordinary-proof`
  dataset is writable/readable by the ordinary client principal only.
- The two principals are independently authenticated through Fuseki/Shiro.
  Administrative dataset creation is performed with a separate third principal.
- The proof executes real SPARQL writes, verifies readback and then attempts
  cross-credential SPARQL Update, GET/query, Graph Store PUT/DELETE, dataset-root
  update, alternative SPARQL route, administrative create/delete/backup and
  anonymous access. Every security rejection must be **401 or 403**, not a
  404/405/500 disguised as a successful security test. Readback then proves
  that the protected RDF was unchanged.
- The container is restarted with persisted TDB2 state and the same hostile
  admission matrix runs again. A fresh directory and isolated localhost port
  are destroyed after the test; no real Pod or PostgreSQL data is touched.
- The verifier accepts only the exact `http://127.0.0.1:3041` URL, explicit
  disposable marker and nonproduction runtime. The pinned fixture users and
  plaintext passwords are **test values only**, never deployment credentials.

The CI workflow `paper-atproto-fuseki-isolation-proof.yml` runs the proof
independently from the existing PG18/Jena crash-recovery and signed repository
workflows. The existing production and signup fuses remain closed.

## Exact security boundary and what is *not* proved

This proves **HTTP credential separation for two different datasets** only.
It does **not** prove independent write permissions between two sets of
triples *inside the same mutable TDB2 dataset*. Apache Jena's graph-level
data access control applies to read-only datasets; it is not a writable
field/graph authorization mechanism. The existing ActivityPods provider uses
the per-Pod triplestore, so this isolated fixture must not be substituted
for deployed authorization without a proper storage redesign.

Shiro dataset authentication also does not prevent a legitimate privileged
administrator, host operator or fully compromised projection credential from
changing protected RDF. It cannot attest independently that the fenced
projection corresponds to a signed PostgreSQL head and current SAI grant.

**Before any production release:**

1. Select and review a write-aware protected storage boundary that does not
   expose the mutable protected RDF to ordinary Pod/SemApps SPARQL credentials.
   A dedicated protected dataset/service is one candidate, but it requires
   integration into existing provider-owned identity, Solid and AP lifecycle,
   not an unaudited detached identity or a second signer.
2. Enforce separate network reachability and rotated secrets for the
   protected writer/reader, ordinary LDP/SPARQL, migration admin and
   PostgreSQL worker. Prohibit the administrator credential from ordinary
   application, Pod or PDS processes.
3. Implement independently trusted Jena readback/attestation binding the
   exact account, DID, signed root/rev/generation, lease epoch and active SAI
   revision to PostgreSQL before acknowledgement. Run real cross-store
   revocation/crash/fencing acceptance with restricted logins.
4. Test failure modes: stale projection, rogue SPARQL write after ACK,
   credential substitution, auth misconfiguration, restart/replay, compromised
   worker, administrator bypass, query/Graph Store alternate routes, backup
   restore and partial outage. Review actual Fuseki container version/digest,
   TLS, secret storage, network policy and deployment migration before
   registration.
5. Preserve provider-owned unified new-account authority and all existing
   production NO-GO switches. Existing account migration remains separate.

## Technical references

- Apache Jena **Fuseki Full Security**:
  https://jena.apache.org/documentation/fuseki2/fuseki-security.html
- Apache Jena **Fuseki file layout**, `FUSEKI_BASE/shiro.ini`:
  https://jena.apache.org/documentation/fuseki2/fuseki-layout.html
- Apache Jena **Data Access Control**, including read-only graph ACL caveat:
  https://jena.apache.org/documentation/fuseki2/fuseki-data-access-control.html
- Existing signed writer / protected projection role acceptance:
  `docs/activitypods-atproto-restricted-repository-writer-pg18.md`
  and `docs/activitypods-atproto-restricted-projection-worker.md`.
