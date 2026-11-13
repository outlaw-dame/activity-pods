# Solid-OIDC Redis grant revocation hardening

Status: source-level security change; release requires exact-head Redis integration and deployment settings verification.

This ports the still-outstanding Redis grant protections from historical PR #148
onto the current ActivityPods master without merging its obsolete stacked
PostgreSQL/signing changes. It changes *grantable* OIDC token indexing and
revocation, not the authority of existing user accounts or the new unified
account release fuse.

## Guarantees

- Redis Lua performs token persistence, grant-index reservation, revocation
  marker check, and bounded TTL in one atomic operation. A client attempting
  issuance after a revoked marker is rejected, not silently accepted.
- A grant may track no more than 512 outstanding token pointers. At capacity,
  issuance returns an explicit error rather than trimming unrevoked pointers.
  Token metadata upserts do not duplicate grant pointers.
- Revocation writes the marker **before** deleting token keys. Readers reject
  marked tokens even if a process terminates partway through cleanup.
- Legacy oversized lists are processed in batches of at most 128 tokens,
  with a hard cap on batch iterations and a recoverable failure.
- Redis scripts have a bounded command count. No `LRANGE 0 -1`, unbounded
  per-grant token accumulation, process-local revocation cache, or second OIDC
  credential database is introduced.
- Disposable Redis 8.2 proof exercises concurrent producers, four Node workers,
  interruption between marker and deletion, legacy-index cleanup, and actual
  Redis MEMORY USAGE samples under a unique namespace.

## Deployment controls still required

The revocation marker remains authoritative only if Redis persistence,
replication/failover and no-eviction policy protect it for the full lifetime
of outstanding grantable tokens. Verify `maxmemory-policy=noeviction`, durable
AOF and backup/failover behavior; never silently fall back to a process-local
allowlist. Monitor admission failures, index size, cleanup bounds, Redis
allocation and connection count. Migrate old, possibly oversized grant lists
by bounded revocation, not automatic truncation. Do not treat synthetic
runner throughput or Redis MEMORY USAGE as production p95/p99 or RSS evidence.

The separate Solid-OIDC client-origin and error-rendering fix is tracked in
PR #170. This change is separate from the still-blocked new unified signup:
real signed PDS, PostgreSQL canonical identity authority, SAI consent and
privileged Jena/Fuseki isolation remain independent release gates.

## Follow-up to post-merge review on PR #171

Two correctness issues were identified by review after the initial merge:

1. The 512-token list cap counted stale pointers to expired/destroyed keys.
   The upsert Lua script now performs **one bounded at-cap scan** of at most
   512 pointers and reconstitutes the index from keys still present in the
   same Redis namespace. It preserves live pointers and extends the index
   TTL as needed. A pre-existing oversized legacy list still fails closed:
   it must be revoked with the separate bounded cleanup path, never truncated.
   This is an infrequent quota-path operation, not a full scan on each issuance.
2. The original revoker performed `LRANGE` before its `MULTI`, allowing
   competing workers to select the same pointers and then trim different
   undisposed entries. Now the next batch's **selection, key deletion and
   pointer removal execute in a single Redis Lua operation**. The revocation
   marker is written first and retained until the maximum token TTL elapses.

Disposable Redis 8.2 checks exercise a full list of destroyed and naturally
expired tokens, live-key retention, four independent revocation processes,
full physical token deletion, replay refusal and legacy oversized list cleanup.
These protect against the two specific review failures; they are not a live
production latency or failover benchmark.

The token index stores logical token keys, as before. Lua reconstructs the
actual ioredis namespace when checking expiry and receives the trusted
key-prefix when deleting batches, so test and provider namespaces cannot be
crossed. Do not run the OIDC grant store in a multi-key Redis Cluster
configuration without an explicit compatible hash-slot and migration design;
the existing atomic grant scripts require their related keys to reside on the
same Redis shard.

