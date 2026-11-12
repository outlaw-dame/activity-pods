# ADSP Phase 0 — ActivityPods Companion

This file links `outlaw-dame/activity-pods` into the cross-repository **ActivityPods Distributed Scalability Program (ADSP)**.

The authoritative program roadmap, invariants, benchmark contract and live evidence ledger live in:

`outlaw-dame/mastopod-federation-architecture/docs/activitypods-distributed-scalability/`

ADSP is patterned after the existing ActivityPub Delivery Migration Program (APDM), but it is a separate program with separate phase IDs. ADSP work does not advance APDM phases by implication.

## ActivityPods authority in ADSP

ActivityPods/SemApps remains authoritative for:

- Pod state and per-Pod dataset isolation;
- LDP and WebACL semantics;
- local ActivityPub execution;
- recipient planning/classification already assigned to Tier 1 by APDM;
- signing/key custody;
- Moleculer broker configuration and service loading;
- service locality for Tier 1 execution;
- serializer behavior and RDF/JSON-LD semantics;
- ActivityPods-side distributed-runtime instrumentation.

The Fedify sidecar remains the Tier 2 external ActivityPub HTTP executor in APDM `external` mode. ADSP transporter experiments must not recreate a second remote delivery authority.

## Phase 0 ActivityPods slice — `ADSP-P0-A`

Phase 0 does not change runtime topology. It freezes the exact current baseline before horizontal/distributed work begins.

Required source/runtime verification:

- [ ] record the exact ActivityPods commit used as the ADSP baseline;
- [ ] locate and record the effective Moleculer `nodeID` configuration and verify behavior with simultaneous brokers;
- [ ] locate and record namespace configuration/default behavior;
- [ ] locate and record transporter selection, including current Redis transporter behavior;
- [ ] locate and record serializer selection and remove any assumption that serializer semantics should depend on transporter choice;
- [ ] inventory which service schemas the default backend process loads;
- [ ] identify high-frequency Tier 1 call chains that should remain colocated by default;
- [ ] identify services/workers that can legitimately scale independently;
- [ ] capture local-versus-remote Moleculer action observability requirements;
- [ ] define representative RDF/JSON-LD remote-call fixtures for later semantic-parity testing;
- [ ] inventory ActivityPods Redis responsibilities so transporter work cannot accidentally overwrite state/cache/queue roles;
- [ ] record a reproducible single-node whole-system baseline for the workloads defined by the ADSP benchmark contract.

## Non-goals for Phase 0

- do not install NATS;
- do not introduce JetStream;
- do not migrate existing queues to Redis Streams;
- do not split every SemApps service into its own process;
- do not alter APDM local delivery, delivery-plan authority or sidecar durability merely to prepare a benchmark;
- do not promote a distributed topology before the baseline and comparison thresholds are frozen.

## Locality requirement

Closely coupled ActivityPods/SemApps operations should remain local when colocated. The program must specifically protect the normal Tier 1 chain around ActivityPub, LDP, WebACL, triplestore and Fuseki-facing work from becoming unnecessary network hops.

The likely unit of horizontal scaling is a **Pod/SemApps cell**, with independent ingress/federation/background groups introduced only where measurements show that separation pays for itself.

## Exit relationship

`ADSP-P0-A` is complete only when the verified ActivityPods facts above are recorded in the cross-repository `STATUS.md` together with the paired federation-architecture baseline. A documentation file alone does not close Phase 0.
