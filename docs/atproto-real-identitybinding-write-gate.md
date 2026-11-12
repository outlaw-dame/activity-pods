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


## Scalability audit and remediation (additional to write fencing)

Two preexisting request paths were unacceptable for local or remote-scale ActivityPods deployment:

- 'identitybindings.getByDid'/'getByHandle' previously called '_findByBindingField', which materialized all account WebIDs and sequentially invoked 'identitybindings.getByCanonicalAccountId' for each account (including up to 10,000 account records on fallback). At scale this is unbounded cross-service N+1 and per-Pod Jena I/O. **The fallback is now removed**: an indexed absence returns no match; a query failure returns a bounded HTTP 503 with 'IDENTITY_BINDING_INDEX_UNAVAILABLE'. An operator/migration must rebuild a missing legacy index in a separately rate-limited bulk maintenance job; API reads must not silently repair by scanning.
- 'identitybindings.list' previously requested *all* indexed binding rows, sorted and filtered them in Node, and on errors scanned account Pods. It now performs one bounded settings-index SPARQL query per page: lexicographic keyset based on 'updatedAt + canonicalAccountId', ordered and limited to at most '(page size + 1)' rows, with a maximum page size 500. A settings dataset outage fails closed without per-Pod fallback. The new cursor parser enforces canonical HTTPS account IDs, normalized UTC ISO timestamps and a 4 KiB encoded cursor maximum.

The critical index must have one unique canonicalAccountId and a single updatedAt per entry; this is currently guaranteed by the whole-index-resource SPARQL replacement within '_syncBindingIndex' on the intended write path, but historical RDF corruption can produce duplicates. Read-time duplicate conflicts must be rejected or repaired offline, *never* resolved by a full account scan. Cursor pagination based on mutable updatedAt is not a transactional snapshot; a production bulk export should use a separate consistency checkpoint or immutable changelog if a strict snapshot is required.

**Cost/performance guard:** zero calls to 'auth.account.find({pagination:false})' on DID/handle/page lookup, zero per-Pod LDP reads for an index miss, one bounded query for each page. Do not enable any speculative auto-rebuild in HTTP handlers. Dedicated node regression tests assert one call and bounded query shape. The next real Jena integration test should verify the keyset query parses and returns the expected ordered pages on Fuseki (not merely that the string contains LIMIT).
