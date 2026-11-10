# Paper Groups — TDB2 writer contention / PostgreSQL decision gate

**Status:** controlled experimental evidence, not production admission or database migration. The current owner, SAI ledger, membership epoch and Group member changes reside in one TDB2 settings dataset, preserving atomic conditional updates.

## Why this measurement

Jena TDB2 is MVCC and supports concurrent readers, but only **one active writer per dataset**. Distributed Moleculer processes and Fedify cells do not remove that serialization. Migration is not justified on theory alone: Group indexed reads are already fast.

The disposable localhost benchmark isolates independent Group member writers using 1, 4 and 16 concurrent writers on the SAME settings dataset. It compares canonical membership CAS against the bounded Group delta-index CAS variant, with 24 distinct changes per writer. Every case validates the resulting membership epoch and unique delta count. It captures per-mutation p50, p95, p99, throughput and HTTP failures.

The run uses synthetic actor IRIs without remote HTTP, Pod ACL, Fedify delivery, SAI broker calls or real user traffic. It is not an end-to-end production throughput claim.

## Acceptance and PostgreSQL decision

- Compare 1, 4 and 16-writer throughput scaling. If total throughput flattens, dataset-level serialization is material.
- Repeat with **normal** Solid/SAI settings traffic, local APDM delivery and periodic Group compaction, publication and GC.
- Record CPU, RAM, disk growth/generations, lock wait, IOPS, p95/p99, failed CAS, backup/restore and dollar cost.
- Benchmark PostgreSQL on matched hardware and workload: Group-scoped membership keys, actor uniqueness, and transactionally checked owner/consent/revision, not a weaker unauthenticated SQL UPDATE.
- PostgreSQL may own operational coordination. **Never dual-write live authoritative membership and consent** between PostgreSQL and TDB2 without a transactional single-authority cutover and verified Solid RDF projection.
- Logical Group page compaction is different from Jena TDB2 database compaction. TDB2 storage compaction may hold up write requests.

## ETag and caching guards

- Public Group descriptions/resources: strong ETags based on exact representation bytes and conditional GET/HEAD only after the normal authorization check; private member rosters remain no-store.
- Membership, bans, live owner, SAI and current epoch: no TTL-only authorization cache. Enforce live database fences.
- Remote recipients/sharedInbox: preserve existing APDM/Fedify authoritative recipient snapshots, not the retired domain-inferred shared inbox cache.
- Cache only immutable, revision/digest-bound bytes after live authorization and measure wins against direct ~9ms indexed TDB2 reads.

## Primary specifications

- https://jena.apache.org/documentation/tdb/tdb_transactions.html
- https://jena.apache.org/documentation/tdb2/tdb2_admin.html
- https://solid.github.io/specification/protocol
- https://www.postgresql.org/docs/current/explicit-locking.html
- https://www.rfc-editor.org/rfc/rfc9110

No Group actor, HTTP route, credential, delivery queue or release fuse is enabled by this benchmark.
