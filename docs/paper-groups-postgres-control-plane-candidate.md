# Paper Groups: PostgreSQL canonical control-plane candidate v1

**Status: isolated, deliberately not deployed.** This is a security and
throughput architecture prototype for Paper Groups and ActivityPods apps.
It is not a replacement for the existing Solid-OIDC/SAI provider, not a
new runtime API, not an enabled Group actor, not a duplicate Fedify queue,
and not a migration of any real member or pod. Existing TDB2 remains
the authoritative member/owner/consent store until an explicit validated
single-authority cutover.

## Why this design

A first matched-host 1/4/16-writer experiment (ActivityPods PRs #127–#128)
showed meaningful PostgreSQL headroom at moderate Group write concurrency,
but did not include production Solid-OIDC, SAI revocation, Pod local
persistence or federation. PostgreSQL's key advantage is row-level
locking among independent Groups rather than multiple writers serialized
behind the same Fuseki TDB2 dataset. The candidate therefore models
**identity lifecycle + consent + Group epoch + membership in one DB**
to prove their serializable *effect*, without dual-writing TDB2.

## Isolation and data model

- Private `paper_groups_candidate` schema with default public table/schema
  grants revoked. An actual deployment must add a least-privilege DB role,
  migration checksum/order and RLS or carefully audited function access.
  This SQL is run only on an empty, disposable PostgreSQL 18 fixture.
- `identities` stores the WebID and active lifecycle revision.
  `consent` stores the **candidate** authorization fence, which is NOT yet
  connected to live ActivityPods SAI. `groups` stores Group revision,
  owner, app, visibility and state. `members` has unique (Group, actor)
  and role/status/revision. `transitions` has one durable operation ID
  and one event per canonical Group epoch; it is an internal audit and
  possible future handoff source, **not** an independent external delivery
  queue. No Group Pods or per-member ActivityPub actor service.
- Partial multicolumn indexes provide directly addressable, C-collated
  keyset membership pages without OFFSET, sort scans or per-recipient HTTP.
  Private reads check the owner and live candidate consent **before**
  returning roster data.

## Transaction authority, locking and revocation

All mutation and roster operations use this single DB lock order:
**owner identity FOR SHARE → consent FOR SHARE → Group FOR UPDATE**.
The locked owner/consent checks are held until the membership update,
Group revision increment and unique transition event commit.

Revocation takes owner identity FOR SHARE then consent FOR UPDATE.
Disable-account takes owner identity FOR UPDATE. The conflicting row
locks wait for in-flight membership transactions, ensuring that once
revocation or suspension commits, no later transaction can update or
read roster based on stale consent. This is stronger than a TTL grant or
an app-side pre-check. A replay with the exact operation ID is idempotent,
but authorization is still checked before returning the replay receipt.
Provider-authorized owner cannot be moved/removed through member API.

**Warning:** The candidate consent is still separate from the running
Solid-OIDC/SAI authority. Without a migration/cutover protocol, its
revocation guarantees are only within the isolated PostgreSQL model.
A successful test here does NOT establish live cross-database safety.

Transactions use strict lock_timeout, statement_timeout and
idle-in-transaction timeout, no external network calls within a DB
transaction, and fail closed on mismatched owner/app, revision or
permission. Lock contention is not solved with unbounded retries.
A production adapter must add a small bounded pool, per-Group admission,
SQLSTATE-specific bounded retry with full jitter for *transient*
deadlocks/serialization conflicts only, operation ID reuse and monitoring.

## Test coverage

Real disposable PostgreSQL integration tests check:

- Initial app/owner/Group provisioning is inert (no Group activation)
- Transactional membership state, exact revision and unique transition
- Operation-ID replay, stale expected epoch, wrong Group and owner changes
- 1,000 synthetic remote member identities with bounded 100-member
  keyset pages and complete sorted/nonduplicated results; stale epoch
  and unversioned next-page cursors rejected
- 100,000 synthetic remote member rows with first/middle/deep keyset
  reads and an EXPLAIN-verified index-based query plan (no table scan)
- Eight independent Groups simultaneously mutated through separate
  connections without lost updates; a second 16-writer/384-mutation
  contention case measures actual consent-row shared-lock overhead
- Revoked consent denies subsequent writes and private roster reads
- A held Group read lock prevents a writer from modifying a page
  mid-snapshot; subsequent roster reads require the expected revision
- Cross-connection held consent lock forces revocation to wait
- Disabled owner denies subsequent writes

## First disposable PostgreSQL 18 results

Evidence: [Group candidate authority CI](https://github.com/outlaw-dame/activity-pods/actions/runs/42898121395), verified against the actual SQL schema and candidate adapter, not an in-memory mock.

- **Nine PostgreSQL integration tests passed**, including revoke concurrency, owner disable, idempotent operation UUID, cross-Group rejection and exact revision-bound cursor pagination.
- At **100,001 rows**, first/middle/deep 100-member pages took 1.84 / 1.64 / 1.67ms respectively in this particular runner sample. EXPLAIN confirmed indexed access rather than a sequential scan.
- With **16 Group writers and 384 total updates**, throughput was approximately 493 mutations/second; p95 44.96ms and maximum 57.7ms in the disposable run.
- These values are samples from one warmed test host, not statistically characterized production p95/p99 or durable SAI-connected operation cost. Concurrent reads/writes on the shared identity+consent rows and WAL/storage behavior need longer tests.

## Production migration acceptance (NOT IMPLEMENTED)

1. A single, authoritative live consent/revocation writer must replace
   the candidate fixture. Do not copy historical SAI rights as an
   indefinitely valid writable grant. Establish a cutover barrier,
   pending-revoke state and reconciliation of in-flight Group operations.
2. Determine whether the ActivityPods Solid-OIDC/SAI server can issue a
   revocation epoch / permission callback that is durably committed to
   the canonical Group DB **before** a user-visible revoke completes.
   If it cannot, require an explicit protocol or retain TDB2 authority.
3. Prove crash/replay, SIGKILL, revoke/approve concurrency, account
   disable, multi-app and cross-Group IDOR, private admission, 1/2/4/8
   cells, 1k/10k/100k realistic actor distributions and backup/restore.
4. Deliver an **approved, sealed** remote-recipient snapshot through
   existing APDM/Fedify authority, not directly from an unverified
   transition event. Fedify's sole durable remote executor remains
   unchanged; no second queue.
5. Map Group RDF read representations onto the canonical SQL state
   without allowing direct RDF writes to mutate canonical membership.
   Preserve WebID, consent and Solid client rights.
6. Measure dollar costs (PG instance/connection pool, Jena, disk WAL,
   Redis, egress), not merely isolated SQL throughput.

## Caching / ETag

No cache is in the candidate's authorization path. Stable public
Group metadata may use strong representation-byte ETags after normal
Solid authorization. Live Group revisions, bans, owner state, consent
and federation recipient authorization must never use a TTL cache
instead of a current permission fence. Private roster responses should
be no-store. Existing signed ActivityPub representations should not
be silently compressed or re-encoded.

## References

- https://www.postgresql.org/docs/current/explicit-locking.html
- https://www.postgresql.org/docs/current/transaction-iso.html
- https://www.postgresql.org/docs/current/indexes-partial.html
- https://www.postgresql.org/docs/current/sql-createindex.html
- https://www.postgresql.org/docs/current/sql-revoke.html
- https://solid.github.io/specification/protocol
