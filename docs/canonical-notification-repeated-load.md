# Measured repeat-window PostgreSQL 18 notification ledger cost/latency

This isolated branch adds a controlled and reproducible repeated-load proof
to the **disposable** PG18 CI workflow; it does not activate the notification
ledger in production.

The proof performs twelve consecutive windows of 512 canonical intents
with four local recipient records apiece (6,144 intents and 24,576 durable
recipient records). Eight async writers share one bounded four-connection
PostgreSQL pool. For each window it records p50, p95, p99, memory RSS and
heap after forced GC, indexed relation size, and durable pending queue
growth. PostgreSQL WAL LSN delta is measured for a write-amplification
cost proxy. The second phase deliberately fails sixteen claimed records
once, advances only their disposable fixture due timestamps, then reclaims
and finishes them. The failed subset receives 32 dispatch attempts for 16
recipient records, showing retry amplification of 2x for that subset.

### Cost calculation

The report estimates `(intents + deliveries + quarantine physical bytes) /
recipient count`, per-million-recipient storage GiB, and per-million
recipient WAL GiB by extrapolating measured byte counts from this fixture.
This is a *physical-storage proxy*, not a hosting bill. Real costs also
depend on WAL retention, replication, PITR backups, CPU time, network
transfer, index/tuple bloat over deletes, retention/deletion policy, and
the database provider/region. Record size and ratio of recipients/intent
also change the answer. The script does not invent a dollar figure.

### Interpretation

A single shared CI runner and local database cannot establish production
throughput, memory-leak freedom, internet p95/p99, real Redis/Redpanda
backpressure, server CPU cost, replica failover or provider pricing. Window
samples detect obvious growth trends but not days-long leaks. The isolated
test retains the source-controlled production release fuse.
