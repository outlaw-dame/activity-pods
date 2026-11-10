# Paper Groups G2 — Local and Remote Delivery Architecture

**Implementation status:** G2-P1 (bounded planning kernel) implemented for review. Member authority, actor activation, local delivery executor, Fedify delivery connector and load validation are **not** yet implemented by this slice. `CONSENT_BRIDGE_RELEASED=false` remains immutable.

## Why this architecture is necessary

ActivityPods' senior-engineering analysis demonstrated a delivery cost problem for **local Pod recipients**, not just remote federation: the 1,000-local-recipient pre-P9 baseline averaged 57,911.3 nested Moleculer actions, 29,303 Fuseki HTTP requests, and 333.538 seconds. Phase 9 improved scheduling using bounded concurrency but did not remove the underlying ~57-action/~29-Fuseki-request marginal recipient cost. Local Pod metadata, WebACL and RDF persistence remain Tier 1 responsibilities; Fedify can only take over **remote** network execution.

Do not create another Group-specific recipient-oriented loop that performs per-user `auth.account.findByWebId`, inbox discovery, remote actor resolution and RDF reads during fan-out. Splitting this pattern into microservices would increase transport overhead without reducing useful work.

## G2-P1 completed components

- `utils/collective-fanout-plan.js`: internal, pure deterministic planning function. It has zero Moleculer calls, Fuseki calls, Redis calls, outbound requests, side effects, keys or authorization decisions.
- Consumes **pre-resolved, authoritative** local targets (`actorUri`, dataset, inbox URI) and remote targets (`actorUri`, inbox URL, optional shared inbox, target domain). It **does not** certify that the snapshot is authoritative.
- Validates canonical HTTPS actor/recipient identities and resolved targets; rejects duplicate/conflicting recipients and malformed dataset keys.
- Maximum 1,000 recipients per bounded page; groups local Pod work by dataset into batches of at most 32. Remote public work groups by distinct sharedInbox **destination** with one intent per URL, even when 1,000 members share it; it must not create 16 duplicate remote POSTs. Non-public visibility does not use sharedInbox, and direct actor inboxes are kept distinct even if endpoints coincide.
- Deterministic plan fingerprints include Group actor, operation intent, visibility, consented membership revision and destinations; not authorization tokens or persisted delivery acknowledgements.
- `tests/collective-fanout-plan.test.js` and the dedicated Actions workload check the 1/10/100/1,000-recipient levels, source-order invariance, conflicts, privacy, bounded batches and absence of broker/network calls.
- `scripts/benchmark-collective-fanout-plan.js` reports planning p50/p95 and process RSS. These measurements **do not** estimate delivery throughput or deployment expense.

No consumer, Group service action, public endpoint or federation queue is wired to this kernel yet. That is deliberate: ActivityPods has no production-active Group actor or authoritative Group membership source in this G1 branch. Exposing caller-provided recipient lists as an authoritative Group-delivery action would be an IDOR and private-membership leak.

## G2-P2 — Membership authority and admission (next prerequisite)

Implement provider-owned Group membership records, policy, roles and revocation that can be queried with bounded keyset pages (not OFFSET or provider-wide scans). A snapshot is valid only with a versioned membership/ACL revision and trusted provider service credentials. Prove owner/admin/moderator authority, visibility, user consent, block/mute and banned member exclusion. The G1 reservation does **not** imply Group actor active status or permission to send.

Each authoritative page should contain the verified actor URI, the membership revision, the complete pagination cursor, and resolved local/remote delivery targets. The snapshot must not include secret or private user data in public API responses. Reject stale revision before committing activity and after recovery. Pages cannot be silently truncated to the 1,000 target cap.

## G2-P3 — Actual Tier 1 local delivery

Integrate with the existing local Pod-cell SemApps path and APDM P10/P11 work rather than write a second inbox implementation. Resolve sender and recipient metadata **once per page** through bounded authority-local operations, preserve WebACL/LDP attachments and visibility, use bounded work queues/backpressure and explicit idempotency. Ensure account deletion and revocation races fail closed. Never turn a service action into HTTP per recipient for local accounts.

Record real p50/p95/p99, nested Moleculer, Fuseki and Redis counts, CPU, RSS, bytes and per-recipient work across 1/10/100/1,000 local recipients. Tests should include a restart between persisted write and acknowledgment, one worker SIGKILL and no duplicate delivery.

## G2-P4 — Actual Tier 2 remote delivery

Do **not** introduce a second publisher, retry queue or signer. Feed the existing ActivityPods `ap.delivery-plan.v1`/durable handoff seam to the Fedify sidecar as the single remote authority, retaining the exact native rollback contract. The Group actor must be active and hold a provider-owned signing identity. Fedify must handle sharedInbox optimization, per-domain rate and concurrency, retries/jitter/DLQ and acknowledgment semantics.

For private or non-public Group delivery, avoid instance-wide shared inbox grouping pending a separate policy/interop validation; never leak membership or hidden addressing. Recheck authorization for new work. Use idempotent intent+activity identifiers and bound per-domain outstanding work.

## G2-P5 — Measured release acceptance

Run the same workload for 1, 10, 100 and 1,000 members split into all-local, all-remote and mixed configurations across 1/2/4/8 Pod cells, both healthy and SIGKILL/restart modes. Demonstrate no duplicate native/Fedify remote sends; no repeated local dataset/actor resolution per member; no unrestricted request fan-out or unbounded queue; no cross-dataset membership leaks. Record realistic cost by measuring exact Fuseki/Redis requests, HTTP network bytes, worker CPU/memory and delivery completion rate—not by extrapolating isolated planning time.

**G2-P1 tests are not a substitute for P2–P5 evidence and must not open the immutable production fuse.**

## Operating cost model to measure

Cost consists of (1) Pod-cell CPU/RAM, (2) Fuseki transaction IOPS and storage, (3) Redis/queue operations, (4) Fedify network egress and signing CPU, and (5) retry/DLQ overhead. Price those separately from measured workload on the intended provider; don't assume a single sharedInbox POST per domain means zero per-recipient local persistence cost. Establish backpressure, quotas, caching invalidation and capacity budgets before enabling broad Groups delivery.

References: `docs/architecture/local-fanout-worked-example.md`, `docs/architecture/activitypub-delivery-migration.md`, `docs/architecture/activitypub-delivery-remote-authority.md`, `docs/paper-groups-g1-performance-review.md`.
