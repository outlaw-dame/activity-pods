# Paper Groups — Storage, caching, ETag and production authority decision (2026-11-10)

## Decision: use TDB2 now; evaluate PostgreSQL as a **single-owner migration**, not an extra authoritative membership database

This architecture is deliberately app-neutral. ActivityPods remains the Solid
and ActivityPub identity/authorization authority; Fedify is the single
external ActivityPub delivery executor. Current provider Group reservation,
membership revision, live owner account and SAI grant ledger coexist in a
single **Fuseki TDB2 settings dataset**. That property allows one atomic
consent/revision/member mutation (without a cross-database commit protocol).
Do not casually turn this into dual writes to Postgres and TDB2.

**Workload decomposition**

| Data/work | Present authority / preferable placement | Reason |
| --- | --- | --- |
| WebID, Solid resources, WebACL/ACP and LDP | ActivityPods/SemApps/Fuseki | Preserve native Solid semantics, existing provider authority and RDF protocols |
| Group actor identity, owner, SAI consent fence, membership epoch and current membership writes | Current settings TDB2 **until separately proven migration** | One transaction today; a hybrid with two mutable truths risks unauthorized joins after revocation |
| Immutable indexed membership pages and changed actor delta | Current provider TDB2, directly addressed by Group+revision | Measured sub-20ms isolated 100k reads; <=512-key CAS delta and bounded streaming compaction; not yet operationally integrated |
| Durable delivery intent/outbox, attempts, destination ACK, failed-job retention, quotas and metrics | Potential PostgreSQL-backed **operational** service, provided it remains an implementation of the single Fedify transport authority | Relational unique constraints, transactionally claimed jobs and indexes suit high-churn tasks; do not duplicate the sidecar's existing Redis/Redpanda producer, leases and idempotency state without a migration/benchmarked simplification |
| Search/discovery | Existing search service, asynchronous projections only | Discovery never authorizes Group participation |
| Page or media bytes | Object storage/CDN as appropriate | Don't store large blobs in membership triples |

**PostgreSQL assessment gate**: benchmark current real TDB2 with parallel
membership mutations, account/SAI updates, page compaction and APDM local
persistence. Collect total Fuseki CPU, write wait time, p95/p99 and disk
growth. Then compare a genuine Postgres candidate against the **same**
1k/10k/100k mixed benchmark on matched hardware, including failure,
backup/restore, storage cost and multi-replica concurrency. If PostgreSQL
wins decisively and we want to move membership to it, plan a single-authority
cutover with one canonical write path, authorization fences preserved,
transactional outbox and RDF/Solid *projection* (not a second mutable
membership database). Ensure group WebIDs and owner authority are consistent
with Solid-OIDC/SAI and that RDF projections do not grant permissions.

TDB2 has multiple readers but only one active write transaction per dataset;
Jena's own storage compaction can stall writes. More sidecars cannot remove
that limit. TDB2 bulk compaction is not the Group's immutable-page compaction.

## Intelligent caching: fail closed on auth, cache only immutable content

**Must not use an ordinary TTL cache:** live authorization, session identity,
SAI grants, Group privacy policy, ban/removal status, current membership
revision, or the authorized delivery recipient set.

**May be tested:** in-request memo for the same immutable Group revision;
content-digest-keyed immutable public Group metadata or materialized pages.
Use a strict entry/byte cap and TTL, but first check current provider
authorization *and epoch* on every private read. Cache keys must include
provider, Group, revision and digest. Never cache an unverified shared-inbox
endpoint per hostname. A cache miss cannot invoke provider-wide scans or
100k remote actor dereferences. Compare p95 CPU/latency and Redis network
cost against the current ~9ms isolated direct TDB2 lookup; a distributed
cache may be a regression.

The Fedify `RemoteSharedInboxCache` is an intentionally retired no-I/O
shim. It must not become a second remote recipient-discovery authority.

## ETag: HTTP conditional transfer, not an authorization or version authority

Solid Protocol permits strong ETags for RDF resources and encourages clients
to send `If-Match` on updates. ETags and `If-None-Match` can save bandwidth
for *stable public Group metadata* and revision-frozen resources, provided:
- the server checks live authorization **before** sending 304 or a cached body;
- public responses vary/partition correctly by representation and user
  authorization, and private rosters use `Cache-Control: no-store`;
- ETags identify the exact bytes/media type of a representation, not a
  guessed Group epoch or a weak hash of a different JSON serialization;
- `If-Match` failure rejects the write, while the actual membership and
  SAI checks remain in the same TDB2 transaction;
- retries after 409/412 never turn a stale ETag into an accepted Group write.

No new ETag-based authorization bypass is activated by this document.
Start on publicly readable, immutable Group description/media responses
only once an actual versioned Group actor endpoint exists and signed HTTP
tests confirm correct 200/304/412 behavior and no cross-user leakage.

## Compression

Keep the existing measured per-layer codec decisions:
- Zstd level 1 for compatible Redpanda producers/consumers with mixed-version
  safe decode/fallback, rather than adding a new codec.
- Gated Brotli quality 0 for bounded Redis Stream envelopes, decode/size
  validated, not forced on small payloads.
- Indexed TDB2 pages currently store <=32KiB uncompressed JSON plus SHA-256
  integrity. Compressing these would introduce decode CPU, compatibility,
  corruption and migration risks; measure real mixed remote URI lengths first.
- Preserve signed ActivityPub body integrity; do not recompress signed bytes
  at the application layer without an explicit HTTP signature/interoperability
  proof.

## Required release gates

Real provider compactor with durable journal, actual multi-writer epoch/lease
fences, verified seal/publish readback and bounded old-generation collection;
a complete consent-first admission writer; APDM local Pod persistence
optimization; sealed remote Group delivery to Fedify with cross-page
sharedInbox dedup, domain fairness and real remote server tests (including
Friendica); SIGKILL, recovery, backup/restore, 1/2/4/8-cell and dollar-cost
workload acceptance. `CONSENT_BRIDGE_RELEASED=false` remains unchanged.

Primary sources:
- https://jena.apache.org/documentation/tdb/tdb_transactions.html
- https://jena.apache.org/documentation/tdb2/tdb2_admin.html
- https://solid.github.io/specification/protocol
- https://www.postgresql.org/docs/current/transaction-iso.html
- https://www.postgresql.org/docs/current/explicit-locking.html
- https://www.rfc-editor.org/rfc/rfc9110
