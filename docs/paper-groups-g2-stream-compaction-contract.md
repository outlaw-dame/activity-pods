# Paper Groups G2 — Streaming Compaction Stage

**Status:** pure, release-disabled compaction stage; no Group HTTP route, signer,
Fedify call, Pod writer, or autonomous database worker.

The `collective-membership-stream-compactor.js` kernel consumes only
provider-verified immutable base page callbacks and one bounded <=512-key
membership delta. It validates Group and revision, ordered actors, no
duplicates, exact expected base member count and exactly one real owner.
The algorithm merges while streaming; it buffers at most a 101-actor
lookahead and 20 output pages (each <=32KiB), independent of the number
of members in a Group. Long valid remote actor IDs are split into smaller
variable-sized output pages without dropping members. Every immutable
output page is staged through a caller-provided provider-owned callback,
and the function returns only a deterministic digest/count manifest.

**Stage is not publish.** The callback does not confer authority; an actual
service must enforce live account/SAI access, verified base/delta snapshot
and a complete durable stage manifest. The upstream G2 delta snapshot
from PR #124 must bind it to the canonical Group epoch. Before any live
publish, prove a complete page/cursor/digest chain against the manifest,
atomically check current Group epoch, ensure no consent revocation,
and fence competing publishers by unique generation/lease. A failed or
interrupted staging operation may leave orphan pages, but **cannot make
them readable** without verified publication.

Production release still needs multi-replica tests with SIGKILL between
every persisted page and every CAS/retry/ack stage, complete durable
staging checkpoints, backpressure as 512 unique keys fill, repair from
corrupt partial stage, rate- and quota-limited old-revision cleanup, and
measured CPU, Fuseki writes, memory and filesystem growth while
other ActivityPods settings/consent updates compete for TDB2's one writer.

For 100k members this necessarily visits roughly 1k immutable base
pages during a compaction. It is **not** run on every mutation, nor
claimed to be free of O(N) periodic work. Measure compaction interval,
amortized cost per changed actor, and worst-case hot Group fairness,
not just one synthetic read.

The stage kernel now includes `readCompactionBaseQuery` and
`decodeCompactionBase`. These keep the original immutable index **base**
readable internally after a membership revision advances, but only when
one settings-dataset query checks the exact expected current membership
epoch, exact base index epoch, live provider account and stable SAI consent.
The read rejects changed revisions, wrong cursor/digest and unauthorized
results. There is no public endpoint or automatic fallback to an unindexed
Group-wide SPARQL scan. The real TDB2 write/replica fault proof is still
required before using this in a running compactor.
