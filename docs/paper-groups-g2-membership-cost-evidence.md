# G2 Membership TDB2 Query-Cost Evidence

This benchmark measures the known risk in the G2-P2 owner-scoped membership
query: `FILTER(STR(?actor) > ?cursor) ORDER BY STR(?actor)` can require
linear group-row work even though the API exposes an opaque keyset cursor.
A cursor alone is not evidence of an indexed query.

## Execution and isolation

`paper-groups-g2-membership-cost.yml` creates a disposable localhost Fuseki
TDB2 settings dataset and destroys it after each run. PR runs collect the
1,000-member smoke probe. The workflow_dispatch input supports exactly
1,000, 10,000 or 100,000 synthetic member rows, never production identities.
The script refuses non-localhost endpoints, any preexisting benchmark Group
record, and the absence of an explicit disposable execution marker.
Do not run against a mounted production data volume or reuse the test fixture.

It creates the minimum G1 reservation/owner account/stable consent ledger and
G2 membership epoch needed to issue real TDB2 reads. It inserts memberships
in bounded batches of 250, then records five requests each for the first,
middle and deep keyset pages (100 members + one lookahead). It verifies
strictly increasing actor keys and exact lookahead cardinality. The JSON
artifact reports seed time, p50/p95/max query latency, read request count
and Node RSS.

A paired exploratory query uses direct literal comparison/order rather than
`STR(?actor)`. Each page runs both query forms in alternating order on the
**same seeded TDB2 dataset**. Their complete actor, role, membership-epoch
and ordering projections must match exactly; otherwise the experiment fails.
The alternative is NOT a production code path and cannot be promoted solely
on isolated timings.

**Not measured:** Fuseki worker CPU/RSS, provider Moleculer calls, actual
local Pod inbox writes, network federation, 1/2/4/8 Pod-cell topology,
throughput under simultaneous writes, retries, remote egress or monetary cost.
Do not equate a 1k smoke test with scalability acceptance.

## Decision gate

Compare the three cardinalities and deep-page latency before authorizing
membership pagination as a component of local or remote Group fan-out.
If deep-page scans grow materially with cardinality, optimize the existing
provider authority with a verified indexed Group+actor projection or an
equivalent transactionally consistent index. Do not move authorization to
Fedify, add a second identity issuer or bypass account/consent checks.

The immutable Group release fuse must remain closed regardless of benchmark
outcome. G2-P3 local Pod delivery and G2-P4 Fedify remote dispatch require
their own real 1/10/100/1,000 recipient cost/fault acceptance.
