# G2 Membership TDB2 Query-Cost Evidence

This benchmark measures the known risk in the G2-P2 owner-scoped membership
query: `FILTER(STR(?actor) > ?cursor) ORDER BY STR(?actor)` can require
linear group-row work even though the API exposes an opaque keyset cursor.
A cursor alone is not evidence of an indexed query.

## Execution and isolation

`paper-groups-g2-membership-cost.yml` creates disposable localhost Fuseki
TDB2 settings datasets, deleting the bind-mounted data before each cardinality.
PR runs measure **1,000, 10,000 and 100,000 sequentially on the same runner**
to reduce unmatched-host noise. The workflow_dispatch input supports one
selected cardinality, never production identities.
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

Compare the matched-host cardinalities and deep-page latency before authorizing
membership pagination as a component of local or remote Group fan-out.
If deep-page scans grow materially with cardinality, optimize the existing
provider authority with a verified indexed Group+actor projection or an
equivalent transactionally consistent index. Do not move authorization to
Fedify, add a second identity issuer or bypass account/consent checks.

The immutable Group release fuse must remain closed regardless of benchmark
outcome. G2-P3 local Pod delivery and G2-P4 Fedify remote dispatch require
their own real 1/10/100/1,000 recipient cost/fault acceptance.


## Initial exploratory evidence (not promotion evidence)

Run [42858449542](https://github.com/outlaw-dame/activity-pods/actions/runs/42858449542)
measured isolated TDB2 membership pages, five samples per cardinality/position,
but each size used a **different hosted runner**. Values below demonstrate
a potentially expensive query and must not be interpreted as matched-host
scaling ratios. These are **p50 milliseconds**, not capacity or throughput.

| Members | First page | Middle page | Deep page |
| ---: | ---: | ---: | ---: |
| 1,000 | 83.71 | 40.57 | 27.95 |
| 10,000 | 400.48 | 128.36 | 37.32 |
| 100,000 | 2119.95 | 1152.18 | 358.22 |

This evidence triggered the matched-host and paired-query tests. Do not
claim an indexed seek or production-read SLA until the new results and query
plans establish it. The CI artifact is retained for 14 days; this table
preserves the initial readings after artifact expiry.
