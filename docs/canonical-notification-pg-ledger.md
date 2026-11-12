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
