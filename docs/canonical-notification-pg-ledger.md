# Canonical notification PostgreSQL ledger — integration gate

**Default: disabled.** The initial implementation is source-fused until an
isolated running ActivityPods provider with real downstream clients has passed
the full failure/replay acceptance test. The stored notification record is
authoritative; an ActivityPub inbox event is a best-effort, replayable
projection with a stable activity ID.

## Deployment architecture

Migration administrator runs
`pod-provider/backend/sql/paper-canonical-notification-ledger-v1.sql`.
The migration creates `paper_notification_ledger.intents`, recipient
`deliveries`, and `quarantine`. A separate NOLOGIN role
`paper_notification_runtime` has bounded data rights, no DDL rights.
Provision a *different* LOGIN credential through the deployment secret
manager and grant it this role; do not reuse Fuseki, the PostgreSQL schema
owner or OAuth secrets.

The provider uses `pg` version 8.23.1 in the backend, with a maximum of two
connections per API process and two per explicitly enabled worker process.
`APODS_NOTIFICATION_PG_URL` is read only after release/feature checks.
`APODS_NOTIFICATION_LEDGER_ENABLED` enables durable ingestion;
`APODS_NOTIFICATION_LEDGER_WORKER_ENABLED` selects only the dedicated worker.
Both are gated by source constant `NOTIFICATION_PG_CUTOVER_RELEASED=false`;
only disposable tests with `NODE_ENV=test` and
`APODS_NOTIFICATION_PG_DISPOSABLE=confirmed` may run until the release review.

Ingest validates the authenticated bridge request before retrieving the
local recipient list. One bounded PostgreSQL transaction locks one intent
manifest and atomically inserts at most 64 recipient notification records;
a conflicting retry (same intent, changed recipients/activity) fails closed.
The HTTP 202/409 is returned **after** that commit, so Kafka may safely
commit an accepted intent even while delivery workers are offline.

A worker claims at most eight due records with `FOR UPDATE SKIP LOCKED`,
and processes at most four concurrently. The 20-second PostgreSQL
lease prevents live replicas from claiming the same row; only the
current lease-token holder may mark it delivered. A crash leaves the work
claimable after lease expiry. Backoff uses capped full jitter; eight
explicit failures atomically move the record to `dead` and insert a
durable quarantine row. No sensitive exception bodies are stored in it.

## Semantics and limitations

The unique (intent, recipient) durable row prevents duplicate *stored*
notifications across retries and multiple API workers. The existing
`activitypub.inbox.post` bridge emits transient in-app events; a worker
may publish then crash before marking its PostgreSQL lease complete.
That can cause a duplicate transient event. Clients and push consumers
must deduplicate by the stable activity ID or read the canonical
PostgreSQL record. This milestone does **not** prove exactly-once WebSocket
or push delivery.

Production onboarding still requires audited migration and rollback,
consistency with every Solid WebACL/SAI policy, owner scope verification,
real HTTP/Redis/Redpanda interruption proofs, retention and deletion
policy, backup/restore tests, multi-node load/RSS profiling and
cost modeling before changing the source-controlled release fuse.
Disposable PG18 p95/p99 figures are comparison baselines, not deployed
capacity guarantees.

The canonical ATProto consent/identitybinding PostgreSQL cutover is a
**different** security boundary. This ledger does not make arbitrary
privileged Fuseki/SPARQL writes safe for repository authorization.

### Worker-crash retry budget

An expired claimed lease now counts as a failed delivery attempt, even when the worker dies before it can call the explicit failure path. The database advances its count under a row lock in the same `SKIP LOCKED` statement that reclaims work. After eight failed lease windows, the record moves to durable quarantine with reason `LEASE_TIMEOUT_EXHAUSTED`. A worker cannot loop indefinitely on the same poisoned notification merely by crashing. The healthy path retains one indexed claim query and at most eight records per worker poll.

### Durable webhook response correlation

The durable HTTP envelope now includes the exact `canonicalIntentId`
alongside `ok: true`, `durable: true`, the duplicate bit and queued
recipient count. A sidecar using strict PostgreSQL acknowledgment must match
that identifier before it advances a Kafka offset. An ordinary HTTP 409 can
also mean a conflicting, rejected manifest; it must **not** be treated as a
completed duplicate without checking the response body. The internal
`activitypods` canonical source protocol is preserved alongside
`activitypub` and `atproto` by the ledger, following the existing
canonical.v1 event schema.

## Controlled load evidence and cost estimation (November 12, 2026)

Real disposable PostgreSQL 18 CI benchmark (not a deployed production provider):

- 8 arrival waves of 128 intents each: 1,024 canonical intents and 2,048
  unique recipient records, with eight async producers and one four-connection
  PostgreSQL pool.
- SQL enqueue latency p50 7.201 ms, p95 13.986 ms, p99 22.197 ms.
  Delivery-state persistence p95 3.349 ms, p99 11.918 ms.
- 273 deterministic one-time transient failures required 2,321 total
  attempts, a measured 1.1333x retry multiplier. Peak backlog 1,154 rows;
  all 2,048 were delivered, backlog zero after ~1.13 seconds of draining.
- Eight forced-GC memory snapshots: process RSS rose 6,803,456 bytes,
  heap-used rose 504,904 bytes. Short-run snapshots **cannot prove**
  production leak freedom. The workload did not run browser clients,
  remote HTTP, WebSocket delivery or push notifications.
- The three PostgreSQL relations and their indexes consumed 1,990,656
  bytes, approximately 972 bytes per delivered recipient under this
  specific fixture. Future reports additionally record WAL LSN growth,
  which is transaction-log activity, not permanent retained WAL size.

**Storage-only sensitivity; not a hosting invoice:** With measured
972 B/recipient, every one million **retained** rows is ~0.972 GB of
these relations and indexes. Railway currently lists volume storage at
$0.15/GB-month, RAM at $10/GB-month, CPU at $20/vCPU-month, and egress at
$0.05/GB. Therefore the isolated table+index portion of 1M retained
records would represent ~$0.146/month in Railway *volume resource charges*,
before all other resources; 10M retained rows ~9.72 GB and ~$1.46 in
that isolated storage component. This is NOT an estimate of total
database hosting cost, which includes persistent compute, WAL, snapshots,
backups, networking, memory, logs, replicas and the underlying plan.
Railway Hobby has a 5 GB per-volume maximum; larger retention would
require an alternate storage layout/plan or a managed database.

Cost inputs must be measured separately for the whole deployed system:
provider API + WebSocket CPU, memory/RSS across 24+ hours, live PostgreSQL
workload IOPS, WAL generation and retention, replication, backup frequency,
network egress, queue poison/dead rows, retention/deletion frequency,
and the cost of multi-zone standby. Monitor `pg_stat_wal`,
`pg_stat_database`, `pg_stat_user_tables`, and
`pg_total_relation_size` on each controlled fixture. PostgreSQL
statistics are cumulative and lag during active queries; take start/end
snapshots and report measurement window.

For pricing comparison, Supabase currently lists Pro starting at
$25/month with 8 GB included disk and $0.125/GB for additional database
disk; it is a managed-service *alternative*, not a direct estimate for
the self-hosted Railway deployment. Compare the full provider+Postgres
bill, not table bytes alone.

Primary references:
- https://docs.railway.com/pricing
- https://docs.railway.com/pricing/plans
- https://supabase.com/pricing
- https://www.postgresql.org/docs/18/monitoring-stats.html

All reported numbers are tied to workflow
https://github.com/outlaw-dame/activity-pods/actions/runs/43173979624
and its exact tested commit. Do not compare measurements across CI
runners as though CPU/disk specifications and concurrent load were
identical. Re-run and record the commit before promotion.
