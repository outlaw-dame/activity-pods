# G2 Indexed Membership Page Projection — Evidence and Safety Contract

**Status:** non-activated direct-lookup projection prototype. The only
canonical authority remains ActivityPods' settings TDB2 membership + SemApps
account + stable SAI consent ledger. No new provider, identity, Pod, group
actor, Fedify publisher, HTTP route, signing key or local delivery executor.

## Measured reason

Matched-host real TDB2 source run
[42859615913](https://github.com/outlaw-dame/activity-pods/actions/runs/42859615913)
showed that changing `ORDER BY STR(?actor)` to `ORDER BY ?actor` does **not**
fix the growing group-wide sort cost: at 100k actors the p50 first page
was 2.166 seconds versus 2.217 seconds for the direct-term alternative.

## Candidate mechanism

The immutable page index builds 100-member pages from a complete,
**authoritative and revision-consistent** snapshot, storing private actor
URI and role data as bounded JSON literals in the existing settings TDB2
dataset. Page IRIs are deterministic SHA-256 keys over
`[canonicalGroupId, membershipEpoch, previousPageLastActorUri]`.
The first page uses a `null` cursor. Subsequent links are exact, non-forgeable
only insofar as the provider enforces caller authorization; cursor hashes
are **not** user authentication. No API or arbitrary client can invoke this
projection in the prototype.

After pages are staged and verified, a conditional same-dataset Fuseki
transaction publishes only the matching indexed epoch, checked against
the Group's *actual* membership epoch, unique active owner, exact reserved
app and stable non-pending SAI ledger. Every reader joins the indexed epoch
to the authoritative epoch and those same owner/account/consent conditions,
then performs a **direct subject lookup** for the page JSON and its SHA-256
digest. Index pages whose revision no longer equals the membership revision
cannot be returned. Reader verification also rejects duplicate results,
tampering, wrong cursor, inconsistent roles and malformed pages.

The real Fuseki proof runs canonical and indexed reads against the same
synthetic 1k, 10k and 100k datasets, verifying identical actor/role/order
and revision for first, middle and deep 100-member pages. It captures both
read cost **and snapshot construction/staging cost**. It tests that
unpublished pages cannot be fetched, and that incrementing the authoritative
epoch makes all previously indexed reads unavailable.

## Non-activation boundaries / open production blockers

This prototype does **not** offer a production-safe index writer.
A real worker must obtain verified snapshot pages solely from the provider's
SAI-authorized membership authority, validate keyset completeness and
revision, and durably reconcile each stage after worker SIGKILL/restart.
Before publishing it must prove *every* page persisted exactly once, with
its complete cursor chain and immutable content digest. No missing page may
be silently accepted. Rebuild must be bounded and backpressured across
multiple Group mutations. Obsolete revision staging must have safe,
rate-limited garbage collection, retention limits and storage quotas.

**Snapshot rebuild on every membership mutation would be O(GroupSize)
write amplification.** It is prohibited to advertise this as production
scalable without a verified incremental copy-on-write page update or a
transactionally consistent indexed membership store. Read performance
alone does not establish total cost or affordability. Until write cost,
repair, resource envelopes, restart and concurrency are proven, this
projection is a candidate, not a replacement for
`collective-memberships.list`.

No public Group membership or delivery route may be enabled by this work.
`CONSENT_BRIDGE_RELEASED=false` remains unchanged. G2-P3 local delivery
still depends on the existing APDM local-persistence program (Phase 11
investigation is open), and G2-P4 external dispatch still reuses the single
Fedify handoff authority. Production acceptance must include 1/10/100/1000
local/remote mixed loads, crash/replay/dedup proof, measured CPU, memory,
Fuseki IOPS, Redis work and byte egress.
