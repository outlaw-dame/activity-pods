# G2 Group-scoped TDB2 delta authority — measured evidence and remaining gates

**Status: reviewed candidate, non-activated.** ActivityPods settings TDB2 is the
sole membership authority. No Group Pod, secondary membership database,
new signing service, Fedify queue, runtime writer activation or route.

## Changes

The opt-in canonical membership CAS now commits:
1. the ordinary monotonic Group membership epoch;
2. the Group `apods:collectiveIndexChangedMember -> hashed member subject`
   pointer;
3. the corresponding member's changed-since-index marker; and
4. the unique changed-actor count (cap: 512);

in **one TDB2 transaction** under existing owner/account/SAI consent fencing.
Partial pointer/marker mismatches abort the mutation. A full delta rejects
the 513th distinct actor **without increasing the canonical epoch**; repeat
updates to an already tracked actor remain possible. This is backpressure
and cannot substitute for the eventual durable compactor.

The read query joins an exact Group subject to no more than 512
changed-member pointers. It returns the live membership revision, indexed
base revision, member roles/statuses and changed count, all under the
existing owner, app, active account and stable consent conditions.
Decoding rejects unknown statuses, duplicate actor/subjects, forged owner,
bad group member hash, revision disagreement, count disagreement or
truncation. This avoids a provider-wide `?member ... changedSinceIndex`
scan.

Index publication now uses the Group-scoped pointer to delete changed
markers, rather than joining all memberships in the provider. A
publication is still contingent on the authorized exact target epoch
and must never occur until the **entire** replacement base is staged and
verified, which PR #124 does not yet implement as a service.

## Observed disposable Fuseki CI

Evidence: [workflow run 42879504241](https://github.com/outlaw-dame/activity-pods/actions/runs/42879504241).
1k/10k/100k synthetic TDB2 datasets, same GitHub-hosted runner, real
SPARQL HTTP calls. 1k used 510 successive new changed-actor mutations
plus prior changed actors, reaching exactly 512 distinct changes.

| Observation | Measured result |
| --- | ---: |
| 1k indexed first 100 members, median | 15.13ms |
| 10k indexed first 100 members, median | 11.93ms |
| 100k indexed first 100 members, median | 9.39ms |
| 1k Group 510 sequential membership changes, median per TDB2 update | 11.96ms |
| 100k Group direct delta snapshot, 5 reads combined | 43.98ms |
| 100k base stage (synthetic 1,001 pages / 51 write requests) | 2,585.61ms |

Caution: CI timings are small isolated samples. No multi-writer race,
SIGKILL/restart, complete mutable index, private-public contract, full
ActivityPods service identity/consent lookup, Fedify, other hosts, provisioned
remote actors, p95/p99 under load or dollar operating cost is proven.

## TDB2 operational constraints: avoid confusing two kinds of compaction

The Group **logical index compaction** described above merges immutable
100-member index pages and <=512 changed members. It is **not** Apache
Jena's **TDB2 storage compaction**.

Official Jena documentation establishes:

- TDB2 has MVCC and serializable transactions, supporting multiple
  simultaneous readers but **only one active writer per dataset**. Adding
  Node.js/Fedify workers does not increase Fuseki's per-dataset writer
  concurrency. Keep membership CAS statements small and bounded; measure
  aggregate write queue time and isolate expensive background builds from
  interactive join/leave operations.
- TDB2 databases must be owned by **one JVM**; multiple app processes
  cannot directly open the same TDB2 directory. Pod cells use the Fuseki
  API rather than file sharing.
- TDB2 storage compaction creates a new on-disk generation and can be done
  live; **writes may be blocked for the duration**, so schedule it with
  capacity headroom and monitor backlog rather than running it on every
  Group revision. Jena also supports consistent live backups. Restore
  testing is a separate release gate, not assumed from a successful backup.

Primary references:
[Jena TDB transactions](https://jena.apache.org/documentation/tdb/tdb_transactions.html),
[Jena TDB2](https://jena.apache.org/documentation/tdb2/index.html),
[Jena TDB2 administration](https://jena.apache.org/documentation/tdb2/tdb2_admin.html).

Therefore test Group membership-write throughput **together with**
normal ActivityPods SAI/account/settings updates, and measure
single-writer queuing, p95/p99, storage generations, backup/restore,
disk I/O and write-stall time. A fast isolated delta read and a
successful single-run CAS do not prove the shared settings dataset is
uncontended or affordable.

## Required next acceptance

- Implement a streaming base/delta compactor that reads the current
  trusted indexed base, overlays the 512 changed actors, stages immutable
  replacements, verifies **all** pages/digests and authoritatively
  publishes only if the Group epoch is still the expected revision.
- Stage without orphaning retention: bounded TTL/GC of old revisions;
  no infinite rebuild loop if a hot Group keeps changing.
- Demonstrate competing writers/compactors and SIGKILL between page
  staging, publication, cleanup, and new membership mutations.
- Prove 1/10/100/1000 mixed local/remote *actual delivery* against APDM
  Tier 1 and Fedify Tier 2, including per-domain dedup and policy revision
  invalidation. The 100k synthetic membership dataset is NOT that proof.

No Group production fuse may be opened by this PR alone.
