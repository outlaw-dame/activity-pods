# ATProto: real ActivityPods identitybinding write boundary

**Draft only / no production repository activation.** This page records the live SemApps adapter contract following the PostgreSQL 18 + actual Jena/Fuseki proof (#142). It is not a migration nor a release authorization.

## Verified code structure

The canonical RDF association lives in the actual per-WebID LDP ControlledContainerMixin of 'pod-provider/backend/services/identitybindings.service.js'. Its resource URI is computed by the service from the canonical account WebID's 'getContainerUri' and the existing SHA-256-based 'atproto-<24 hex chars>' slug. The global 'settings' SPARQL index is a lookup projection, **not** the canonical identitybinding.

The legacy 'upsert' action constructs a complete LDP resource and calls PUT/POST, while 'remove' can delete it; both were written before the new 'repoProjectionFence' predicate. Such operations can destroy a fenced root/revision/epoch. In this PR, both actions fail closed when an existing protected LDP binding advertises *any* 'repoProjectionFence' representation (plain, prefixed or expanded IRI), even a malformed value. This is a defensive compatibility guard, not the actual atomic writer.

## Important unsolved concurrency boundary

A read-time legacy guard does **not** close the race when another worker fences the RDF resource **after** the legacy read but **before** the legacy PUT/DELETE. Production registration must therefore *not* occur until the canonical protected LDP mutation path rejects all unfenced operations at the same atomic triplestore update boundary, or legacy mutations are disabled entirely while the fenced binding is in use. Do not claim the current compatibility guard is sufficient to protect live writes under multi-replica contention.

The explicit next integration must:

1. Resolve the protected RDF resource and dataset via authoritative SemApps container location and storage routing, never by deriving a dataset from an arbitrary user URL or trusting user-selected SPARQL graph names.
2. Add and test the ontology/context interpretation of 'repoProjectionFence', read-back in the identitybindings DTO, and consistency with JSON-LD/LDP canonical resource serialization. Use both literal and URI representations where actually supported.
3. Add a privileged, conditional Jena update that compares exact canonical actor/WebID/DID/root/rev and monotone epoch at mutation time, with provider-only authorization and grant-version fencing. Prevent stale LDP full-replace, delete and legacy 'upsertRepoBootstrap' from racing it.
4. Re-read the LDP canonical resource (not the 'settings' index), ensure the index is synchronized/invalidated, and fail closed on discrepancy. Backfilling and repair must be explicit, audited and idempotent.
5. Exercise three or more real Moleculer replica processes, process kills and partitions, delayed writes, grant revocations, identity changes and zero false-positive readiness against real per-user Jena datasets. Only then consider a separate signed activation release.

## Cost and scaling

Keep the recovery ledger's per-account row plus selective due-job/expired-lease partial indexes. Use bounded SQL pools and conditional epoch-claim updates rather than holding a DB connection through network or Jena I/O. Prefer event-driven reconciliation plus bounded batch scans to indiscriminate per-request SPARQL population scans. Cryptographic signature checks and the external PLC/handle verification should use controlled concurrency and correctly fenced caching; no stale or unverified material can grant authority after revocation.

## Current guarantee

The helper in 'utils/identitybinding-fence-policy.js' rejects legacy writes/deletes *after a previously fenced binding is observed*. Its dedicated Node tests cover absent bindings, malformed/duplicate RDF fence values, and unknown operations. It is intentionally not a replacement for durable PostgreSQL/Jena fencing and remains unrelated to passkey authentication.
