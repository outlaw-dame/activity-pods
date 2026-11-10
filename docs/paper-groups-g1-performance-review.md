# Paper Groups G1 — performance, scalability and security review

**Status:** Review evidence, not a production throughput claim.  
**Scope:** PR #117, provider-owned Group authorization, SAI mutation ledger,
reservation and Solid-OIDC Client ID document resolution.

## Existing ActivityPods engineering constraints

Follow `docs/architecture/scalability.md` and
`docs/architecture/benchmarking-and-capacity-evidence.md`. In the real
ActivityPub Phase-8 1,000-local-recipient baseline, the project measured about
57,911 nested Moleculer actions and 29,303 Fuseki HTTP requests, with roughly
333.5 seconds wall time. Those are **delivery baseline** measurements, not
Groups measurements. The lesson is to remove duplicate authority lookups,
unbounded population scans, repeated materialization, and excessive per-item
cross-service work before changing hardware or transport.

Phase-1/2 Pod-cell work additionally established: local-first Moleculer
execution, no cross-node SemApps registry bootstrap, monotonic authoritative
recovery across worker loss, and per-Pod ownership of LDP/WebACL operations.
Groups must not regress any of those invariants.

## Group path review and implemented safeguards

| Area | Current contract | Evidence / limitations |
|---|---|---|
| Reservation insert | One deterministic, subject-bound TDB2 conditional INSERT in the provider `settings` dataset; no provider account-population scan | Real Fuseki G1 proof with races/restart |
| Reservation read | Subject-bound SELECT with LIMIT 2; no OFFSET or unbounded Group enumeration | `collective-reservations.test.js` + Fuseki proof |
| SAI consent | Account check, registration lookup and app-filtered special rights. Per-Pod records are read from their owning Pod dataset | Live provider HTTP SAI and two-dataset persisted proof |
| Revocation | Durable settings-dataset pending marker preempts Group reservation commit; revisions prevent stale idempotent replay | Native SAI grant/revoke/regrant/unregister and real Fuseki proof |
| Work-count growth | Independent 3,000-record fixture must not increase per-request Moleculer call counts or broaden reservation SELECT | Unit Tier-A **work-efficiency guard**, not capacity benchmark |
| Distributed runtime | Existing Redis-backed Pod/SemApps cell retains prefer-local behavior; no new separate Group Pod, actor issuer, queue or delivery authority | Existing ADSP P1 locality and P2 horizontal/node-loss CI |
| OIDC discovery | Existing native Solid-OIDC issuer and same canonical HTTPS app URI for client and SAI. No new auth or passkey system | Real native PKCE/JOSE HTTP proof |
| Remote Client ID fetch | 6-second request timeout, 64 KiB body bound, no redirects, public-network DNS/socket validation and capped socket concurrency | `collective-oidc-client-document.test.js` and disposable provider |
| Bootstrap/recovery | Initialization is one-time and fail closed; offline recovery is revision-CAS and never silently grants rights | Real Fuseki proof and offline recovery tests |

**Important:** A live SAI check is intentionally repeated around the
reservation INSERT. Do **not** remove one check just to reduce calls: the
pre/post check complements the same-dataset atomic fence and detects
cross-dataset revocation ambiguity. Consider combining independent reads only
after an actual workload benchmark proves equivalent authority and
revocation behavior. Do not introduce Redis caching of positive consent:
read-your-revocation correctness takes precedence over cache hit rate.

## Local **and** remote scaling acceptance contract

The senior engineering finding did not apply only to remote federation.
Previously, **local** follower inbox placement and recipient resolution also
amplified nested Moleculer service calls and Fuseki lookups. In a historical
analysis, ~40 internal calls per recipient across ~200 recipients meant ~8,000
internal round-trips for one post before considering federation. A delivery
throughput measurement of 1,000 local recipients observed 57,911 broker
actions and 29,303 Fuseki HTTP requests. These are separate historical
workloads; do not combine their figures as if measured simultaneously.

**G1 intentionally has no Group membership fan-out, inbox delivery,
federation, AP Group actor key issuer, ATProto publish queue or subscription
enumeration.** Group authorization and reservation paths are per-app,
per-principal and per-canonical-Group-key only, and must not grow with
the number of local or remote Group members.

Before a later G2 member/discussion/event delivery system can be enabled:

- **Local delivery:** build one immutable recipient plan per source activity;
  determine Pod locality and authorization in bounded batches, then write
  to recipient Pods with bounded concurrency while preserving per-Pod dataset
  and WebACL authority. Avoid per-member repeated actor, Pod, permission,
  attachment or metadata reads, and never replay local delivery as remote.
- **Remote delivery:** use the single chosen Fedify delivery authority with
  ActivityPub sharedInbox grouping by receiving instance where supported.
  Do not run native ActivityPub and Fedify outbound delivery simultaneously.
  Keep at-least-once retries idempotent with backoff and deduplicated
  provider/instance batches, not one queue job per user by default.
- **Microservice boundaries:** separate independently scalable ingress,
  federation, search projections and background work from the hot Pod-cell
  paths. Co-locate LDP/WebACL/Fuseki-facing authority operations for the
  owning Pod. More broker boundaries do **not** automatically improve
  throughput; profile service discovery, RDF serialization and local-versus-
  transported call counts before extraction.
- **Load evidence:** compare 1/10/100/1,000 local members and matched remote
  cohorts on the same image/hardware. Record local vs transported
  Moleculer calls, Fuseki/Redis request counts and bytes, delivery outcomes,
  duplicate work, latency p50/p95/p99, throughput, CPU, RSS, backpressure and
  restart/SIGKILL recovery. Require roughly bounded per-activity planning
  overhead, not ~40 broker calls multiplied by each member.
- **Consent revocation and privacy:** a cached recipient plan is immutable
  for an already authorized operation; new authorization decisions must
  check current membership/consent. No privately scoped Group content may
  leak through queues, projections, federation batches or retries.

No performance claim for those future delivery workflows is implied by
PR #117's passing Pod-cell/Redis/node-loss CI or the Group 3,000-record
work-count test. Those are **necessary platform invariants**, not G2
acceptance results.

## Residual performance and security gates

1. **No measured Group capacity ceiling yet.** The 3,000-record regression
   controls operation count, not Fuseki physical query cost. Test subject-bound
   query plans as settings-dataset cardinality grows and report query/update
   p50/p95, Fuseki request totals, JVM/heap, disk/page cache and RSS on
   identified hardware.
2. **No activation/federation throughput claim.** Public Group creation,
   worker provision and Group AP/AT keys/DIDs remain unavailable under the
   immutable `CONSENT_BRIDGE_RELEASED=false` fuse. Actor/federation/ATProto
   cost and retry/backoff behavior must be measured in a future G2 slice.
3. **Multi-replica SAI mutation fencing must be proven under loss.**
   Existing Pod-cell node-loss CI covers platform workloads; it is not an
   end-to-end distributed SAI grant/revoke-versus-Group-commit test.
4. **App-allowlist rollout requires quiescent policy coordination.**
   A rolling deployment where old and new replicas disagree on app approval
   must not be called atomic.
5. **The OIDC URI-document network policy is defense in depth, not an
   egress firewall.** Enforce provider network segmentation and disallow
   access to host metadata, Redis, Fuseki admin endpoints and private
   infrastructure in deployment policy.
6. **Review and merge remain separate.** Human approval and independent
   security review of actual HTTP/LDP bypass surfaces are mandatory. CI
   passing with the release fuse closed does not authorize enabling it.

## Before/after evidence rules

For new performance optimizations, collect a fixed workload and compare
**successful useful outcomes**, Moleculer actions, Fuseki queries/updates,
serialized bytes, CPU time, heap/RSS, and p50/p95 with the same backend image
and hardware. Never infer universal capacity from a GitHub-hosted runner.
Use keyset paging for any later Group discovery/list endpoint; avoid OFFSET,
unbounded container materialization and provider-wide account scans.
Batch only within one authoritative dataset and preserve the user's Pod
ownership. No duplicate remote ActivityPub delivery path may be introduced.

**Deployment outcome:** This G1 review makes no promise of faster wall time or
higher user capacity. It establishes bounded control-plane work, more secure
remote client resolution and reproducible acceptance tests without bypassing
the disabled release gate.
