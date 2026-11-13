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
