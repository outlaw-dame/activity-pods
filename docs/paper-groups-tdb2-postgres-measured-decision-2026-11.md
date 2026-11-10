# Paper Groups storage decision — measured TDB2 and PostgreSQL workloads

**Date:** 2026-11-10. **Release status:** Experimental evidence only; no
new database dependency, shared-index runtime activation, Group AP actor,
Fedify delivery queue or permission cache is enabled.

## Evidence and reproducibility

- [Real TDB2 single-dataset contention run 42891109389](https://github.com/outlaw-dame/activity-pods/actions/runs/42891109389)
  from merged PR #127.
- [Matched-runner real TDB2 vs PostgreSQL 18 candidate run 42892123530](https://github.com/outlaw-dame/activity-pods/actions/runs/42892123530)
  from merged PR #128.
- Repeatable scripts: provider backend proof-collective-tdb2-writer-contention.js
  and proof-collective-postgres-writer-contention.py.
- All samples: 24 distinct membership CAS mutations per writer, one owner
  and one stable consent ledger, separate independent Groups at 1, 4, 16
  writer concurrency, validation of exact persisted Group revision and
  unique changed-member counts.

| Writers | TDB2 legacy writes/s | TDB2 indexed writes/s | PostgreSQL legacy writes/s | PostgreSQL indexed writes/s |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 64.12 | 77.32 | 791.04 | 732.33 |
| 4 | 113.51 | 103.93 | 1536.28 | 1545.38 |
| 16 | 125.49 | 123.23 | 1204.52 | 695.04 |

| Writers | TDB2 indexed p95 (ms) | PostgreSQL indexed p95 (ms) |
| ---: | ---: | ---: |
| 1 | 14.89 | 2.41 |
| 4 | 44.81 | 3.71 |
| 16 | 146.52 | 66.81 |

**Interpretation:** TDB2's one active dataset writer is a real
concurrency risk: throughput improves modestly as write contention
increases, while latency rises. PostgreSQL's candidate transactions
indicate meaningful headroom for independent Group writes, but its
16-writer indexed case slows substantially compared with 4 writers.
Do not assume unbounded scaling from a different database.

**Comparison limitations:** PostgreSQL is reached via native psycopg
with straightforward relational indexes, while Fuseki uses HTTP SPARQL
and RDF serialization. Only one short run per scenario and no random
scenario ordering, confidence intervals, real SAI broker checks, local
Pod writes, ACTUAL remote actors, Group admissions, APDM, Fedify,
storage-compaction outages, restart, cost or capacity envelope.
These numbers CANNOT be represented as direct database-engine
speedups or production throughput.

## Decision

1. **Keep** ActivityPods WebID, WebACL/ACP, Solid resources, Pod LDP
   and RDF exposure on Jena/SemApps for the foreseeable future.
2. **Continue** current TDB2 Group membership for non-activated G2,
   retaining atomic live owner/consent/revision checks and the bounded
   index/delta plus streaming immutable generation compaction.
3. **Evaluate PostgreSQL seriously** as a possible **sole primary
   Group operational state store**: membership, roles, requests,
   Group revocation barrier, per-Group epoch and transactional outbox.
   Fast read-only RDF views/projections would be rendered from the
   canonical committed state. This is a distinct future migration.
4. Before migration, create and prove a **single consent authority
   boundary** across Solid-OIDC/SAI and Group membership. A request
   cannot commit based solely on an earlier SAI check if SAI revocation
   can occur between that check and the SQL transaction. A deny-first
   revocation barrier, observed fencing epoch and in-flight transaction
   drain must be proved under concurrent revoke/join and SIGKILL.
5. **No dual-write membership** as independent authority in both
   Postgres and settings TDB2. No caching of bans, active consent,
   owner rights or current Group epoch to bypass the live fence.
6. Re-run matched benchmark through actual Moleculer and SAI/Pod
   services, TDB2 writer compaction, 1/2/4/8 cells and 1k/10k/100k
   member distribution; measure throughput/p95/p99, CPU, RAM,
   IOPS, storage growth, replication/backup and dollar cost.

## TDB2 mitigation now (regardless of eventual PostgreSQL decision)

- Keep one bounded transaction per Group mutation, no N recipients
  -> N broker/Fuseki calls. Never rebuild the full Group index per
  membership change.
- Read directly addressed <=32KiB immutable membership pages;
  append at most 512 Group-scoped changed members per base
  generation. Compact asynchronously, stage in bounded batches,
  verify all persisted pages/digests, and CAS-publish only an exact
  approved revision. A full 512-key delta must backpressure new
  distinct changes **until compacted**, not silently drop writes.
- Limit parallel write-heavy jobs per settings dataset (not just per
  service instance); dedicate worker capacity and monitor
  serialization backlog and p99. Prefer fair, bounded admission and
  no unbounded retries.
- Use shorter read transactions and avoid in-request global scans,
  unnecessary JSON-LD expansion and remote dereferencing.
- Distinguish Jena/TDB2 storage generation compaction (which can
  stall writes) from Group logical index compaction. Monitor
  maintenance and practice backup/restore on disposable databases.
- Keep Fedify remote egress and APDM local Pod persistence separate
  from hot Group membership writes; dedup remote sharedInbox only
  from authorized concrete recipients, never per-domain guessing.

## ETag and caching (compatible, selectively useful)

**Solid HTTP strong ETags** are useful for immutable or slowly
changing publicly readable Group actor metadata, resource bytes and
representations. ETag should hash **exact representation bytes**
including RDF content negotiation/serialization, and be evaluated
only AFTER the usual authorization check; use If-None-Match/304 on
safe reads, and If-Match/412 for conditional mutations when an
actual endpoint exists. Membership revision CAS remains the real
write fence. A 304 must never disclose a private resource exists.

**Do not add a distributed membership authorization cache.** Its
invalidation cannot reliably enforce immediate revocation when a
remote or local member is banned. Membership roster responses
should remain no-store. Content/digest-keyed immutable pages
may use bounded per-request memoization *after* current epoch/SAI
verification if a multi-operation caller benefits; no Redis cache
unless its hit rate/CPU/network p95 is measurably better than the
already fast ~9ms direct indexed TDB2 read.

Private, authenticated HTTP responses must not leak through public
CDN caching. Apply RFC 9111's Authorization/no-store/private rules
and never assume Set-Cookie blocks caches. Preserve signed ActivityPub
body bytes for federation interoperability.

## Primary sources

- https://jena.apache.org/documentation/tdb/tdb_transactions.html
- https://jena.apache.org/documentation/tdb2/tdb2_admin.html
- https://solid.github.io/specification/protocol
- https://www.postgresql.org/docs/current/explicit-locking.html
- https://www.rfc-editor.org/rfc/rfc9110
- https://www.rfc-editor.org/rfc/rfc9111
