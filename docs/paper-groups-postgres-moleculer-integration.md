# Paper Groups — PostgreSQL + Moleculer integration plan and bounded candidate

**Status 2026-11-10:** This branch has a test-only, manually imported
`backend/candidates/collective-postgres-moleculer.js` adapter. No
production service glob imports it; the live TDB2 membership authority,
Solid-OIDC/SAI provider, release fuse and Fedify executors are unchanged.
Even a process-wide env flag cannot activate the candidate: it requires an
explicit `fixtureOnly: true` construction at test time and a separate
`settings.enabled: true` override.

## Why Moleculer remains appropriate

The ActivityPods scalability findings came principally from amplification
inside handlers: N recipients triggering N Moleculer actions and repeated
Fuseki HTTP calls, actor dereferences, broker metadata work and redundant
local/remote delivery. Moving the *same* N-per-member actions to SQL would
not fix the algorithm. Keep the Group control plane as **one bounded
Moleculer operation per mutation or page**, with short PostgreSQL
transactions, immutable revision-bound reads, no network calls within locks
and the existing APDM-to-Fedify delivery boundary.

This candidate accepts a **single injected node-postgres Pool per
process**, with one connection borrowed for a complete operation and
released in `finally`. It does not create a pool per Group/user/action,
nor open secondary Redis, Kafka or federation paths. It checks exact
Group ID, owner identity, app consent, Group revision and operation ID in
one SQL transaction, with row locks in the order identity FOR SHARE,
consent FOR SHARE, Group FOR UPDATE (mutation) or FOR SHARE (page).
`SET LOCAL` bounds lock wait and statement/transaction idle time. Paging
uses the existing composite (Group, actor COLLATE C) PostgreSQL index and
requires the exact revision on every follow-up page.

**The candidate is not authorized for live use.** Its consent table is
populated only by a disposable fixture, not by the live SAI provider.
Do not expose `change` or `list` to an HTTP route or feed until a
single-provider consent authority/cutover protocol has been proved.

## Bounded connection budget / cost controls

For C ActivityPods app cells and P connections per cell, expected worst-case
direct PostgreSQL connections is approximately C*P plus maintenance
headroom. Start with P=2–4 (candidate proof uses max=4), measure pool
wait-time, active/idle connections, DB CPU, memory, lock queue and p95/p99,
then adjust. For an eventual 8-cell setup, a 4-connection pool per cell
implies up to 32 app connections, not 8*100. If using PgBouncer transaction
mode, test prepared-statement/session-settings compatibility: use
transaction-scoped settings and row locks only; no session advisory locks.

Use one bounded DB transaction per membership write, not 1000 per recipient.
Prefer conditional UPSERT and unique operation IDs, no unbounded retries.
Limit retries to observed transient SQLSTATE 40001 and 40P01, with small
bounded full jitter, and never reissue an unauthorized or stale request.
All change commits include the member, epoch and private transition record.

Keep indexes to measured queries. A 100k-member synthetic fixture with
the optimized partial active index took about 36.3 MiB inclusive of table
and indexes; this is *not* a real cost forecast. Tune autovacuum per
table using observed dead tuples, monitor WAL writes, checkpoints,
connection memory, backup/restore and storage amplification, and avoid
routine VACUUM FULL. Consider WAL LZ4/Zstd only after measuring actual
CPU/disk and restore compatibility; never disable fsync or full-page
writes for benchmark optics.

## Cross-store consent cutover: must be atomic in effect

Live SAI consent revocation currently resides in ActivityPods/Solid/Jena.
The Group PostgreSQL candidate cannot rely on checking it **before** a SQL
transaction, because consent can be revoked before that transaction
commits. Nor can TTL cache, ETag, a 30s HMAC grant, or ordinary JWT
expiration solve this race.

A production authority migration needs one enforceable protocol:

1. Register provider principal and a monotonic authorization generation
   through the existing Solid-OIDC provider.
2. Under a deny-first barrier, prevent new Group writes in the **candidate
   DB** before a revoke can be acknowledged externally. Drain/deny
   in-flight Group SQL operations using the same consent row lock.
3. Make the existing SAI revoke endpoint call a durable idempotent
   control-plane transition. If it cannot reliably commit the PostgreSQL
   barrier (including network partitions, SIGKILL and rollback) **before**
   acknowledging revoked rights, do not migrate Group write authority.
4. Cut over once with a manifest of Group revisions and member counts;
   verify the last TDB2 revision and SQL ledger state. Solid/RDF data
   becomes an authenticated, read-only projection of SQL, not a second
   writable Group membership store.
5. Prove source-of-truth recovery after interrupted export, partial
   revocation, duplicate webhook and all 1/2/4/8-cell races.
   Keep TDB2 primary until those exact tests pass.

The long-term primary Group operational database may be PostgreSQL,
but identity, WebID, Solid Pod resources, ACLs and interoperable RDF remain
with ActivityPods/Jena until a **separate** account-authority migration.

## Candidate v2: durable deny-first consent receipt

The v2 SQL migration adds `consent_revocations` with unique
(owner_webid, app_uri, operation UUID) and (owner_webid, app_uri,
resulting revision). It adds **one small event per actual revocation**,
not per membership change or remote follower. The non-activated
Moleculer `revokeConsent` candidate locks the identity row FOR SHARE
(even if disabled), consent FOR UPDATE, conditionally updates
`granted=false, revision=revision+1`, and inserts the receipt in one
transaction. Repeated operation UUID returns the exact committed
result only while that revocation is the latest consent state; a
later regrant or different input revision rejects stale replay.

All membership operations hold the exact same consent row FOR SHARE
before their Group FOR UPDATE lock, so a PostgreSQL revoke cannot
become visible while an earlier mutation remains uncommitted. A new
mutation after revoke commits fails. The real PostgreSQL integration
proof holds a consent row lock on one connection and verifies that
another connection's revocation cannot finish until the first
transaction releases it; then it checks durable receipt and
post-revoke denial. Do not substitute an ordinary TTL/cache/pubsub
event for this commit barrier.

**This currently proves only an internally consistent PostgreSQL
candidate**, not an ActivityPods Solid-OIDC revoke. Runtime integration
must carry a *verified server-side* SAI event with an authenticated
source and operation UUID; an ordinary Group owner or application must
never invoke this provider maintenance action. The cross-store
protocol must commit the PostgreSQL deny barrier before the live
provider tells the user SAI access was revoked. If PostgreSQL is down,
revoke acknowledgement cannot succeed on a stale/ambiguous grant:
mark authorization pending/denied and repair idempotently. Future
regrant requests must carry a new SAI consent epoch and cannot
reactivate an earlier revoked authorization without fresh approval.

Record PostgreSQL write-lock waits and revocation transaction
latencies, but do not log application grants or user member lists.
Keep a bounded retention policy for already-reconciled revocation
events only after restart/recovery/idempotency windows are specified.

## Beyond Groups: PostgreSQL scope evaluation

**Good candidates for PostgreSQL, after separate performance and security
research:** application-facing operational account *associations* such as
Group invitations, roles, moderation records, notification delivery state,
per-user subscription preferences, account-to-Group join-request workflow,
idempotency receipts and internal durable synchronization metadata. These
are relational, transactional, often mutable and may benefit from indexed
foreign keys, partial indexes and row-level concurrency. Avoid copying
sensitive metadata into unnecessary duplicate systems.

**Conditional future candidates:** account directory and lifecycle
projection, aliases, app installation state, sync checkpoints and
user-facing social graph. These require consent/deletion and federation
semantics, migration-proof canonical ownership, and read/write workload
measurement. A generic follow graph may be cached/projected, but it is not
the same as private Group membership.

**Keep on Solid/Jena initially:** authoritative WebID and Pod identity,
Solid-OIDC/SAI provider rights until cutover, RDF resources, WebACL/ACP,
LDP content, user-controlled linked-data representations and portability.
Moving the ordinary account record too early would risk splitting login
or authorization identity between stores.

Recommendation: migrate **Group control-plane state as one bounded
domain**, do not simultaneously migrate the entire ActivityPods account
system. Evaluate account associations individually with exact lifecycle
and ownership contract; a wholesale platform rewrite would introduce
unbounded architectural drift and operational risk.

## Required before merge to runtime

The current CI proves an isolated single provider authority and bounded
Moleculer adapter under a disposable PostgreSQL 18 container. Release
requires pinned node-postgres dependency and reproducible lockfile, real
Moleculer broker integration across multiple cells, durable provider
SAI callback and exact grant credential, least-privilege roles, TLS,
schema migration strategy, Sigkill/retry tests, queue/connection budget
and backup/restore. No production flag changes in this PR.

Primary docs:
https://www.postgresql.org/docs/current/explicit-locking.html
https://www.postgresql.org/docs/current/routine-vacuuming.html
https://www.postgresql.org/docs/current/runtime-config-wal.html
https://node-postgres.com/features/pooling
https://solid.github.io/specification/protocol
