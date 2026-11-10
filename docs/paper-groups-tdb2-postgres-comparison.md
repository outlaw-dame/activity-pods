# Paper Groups: first matched-host PostgreSQL candidate comparison

**This is a candidate database benchmark, not a migration or deployment.**
The target Group model still uses TDB2 settings as the canonical membership,
consent and owner authority. The comparator creates a *disposable* local
PostgreSQL 18 schema with owner/account, live consent, Group revision, members
and unique changed-member index; each mutation verifies permissions, locks
only its Group row, updates the member, updates the delta unique count and
increments membership revision in **one SQL transaction**. The TDB2 comparator
runs the same 1/4/16 independent Group writers with 24 mutations each,
including its analogous same-dataset owner/consent and revision fences.

Both databases run on one disposable GitHub CI host in one job. All Groups
verify their final epoch and member count. This makes the difference in
throughput *informative*, not scientifically exact: PostgreSQL uses an in-
process psycopg driver; TDB2 uses HTTP SPARQL and RDF serialization.
Connection pool warmup, transaction/batch differences, JIT/IO/VM variance,
database sizing and application work remain unaccounted for.

**Before any PostgreSQL adoption** compare end-to-end authorization and
SAI revocation concurrency (including revocation races), membership churn
for 100k-member Groups, Group membership mutations plus ordinary Pod/SAI
updates, TDB2 snapshot compaction overhead, multi-replica restart and
backup recovery, full Fedify recipient handoff and cost of managing two
stores. Ensure PostgreSQL is a **sole authority** for any moved Group data,
not an independent copy of changing TDB2 membership state. RDF exposure
must be a governed Solid projection, never an alternate writable permission
store. A transactional outbox and a deny-first revocation barrier are
required across any migration boundary.

Postgres may be appropriate for high-churn Groups and durable coordination
if write concurrency substantially improves and compensates for migration
and storage complexity. Otherwise retain the existing measured TDB2 path,
reduce per-recipient writes and isolate background index work.

No PostgreSQL dependency is added to the ActivityPods runtime by this PR.
No cache or ETag controls are activated. All release fuses remain closed.
