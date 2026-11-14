# Paper unified new account: signed hosted-PDS readiness and post-seal completion

**Status: NON-ACTIVATED, test-only ActivityPods integration.**
This applies exclusively to *new* unified WebID/AP actor + managed ATProto
`did:plc` accounts. No existing account adoption, linking or migration.

## Problem resolved in this gate

The previous cross-authority verifier intentionally accepts only a
`reconciliation_required` signup. It can produce one durable
`evidence_sealed` journal operation, but cannot be reused afterward; doing
so would bypass the original uncertainty/side-effect recovery design.

The new `postseal-signup-completion-evidence.mjs` is a separate **read-only**
provider verifier for `evidence_sealed` operations. It independently checks
the unchanged account generation, complete protected Solid/SAI bootstrap,
WebID = ActivityPub actor, managed DID, handle, PDS, real signed PostgreSQL
head and current applied RDF projection. It then demands a current canonical
PostgreSQL identity and app grant with a monotone consent revision.

`hosted-signup-pds-attestation.mjs` additionally verifies the **actual hosted
HTTP response**, not a `repoInitialized:true` Boolean:

1. Check the current managed-provider signed head, DID/handle and exact
   protected projection fence before any external call.
2. Fetch `com.atproto.sync.getLatestCommit`, `getRepoStatus`, and
   `getRepo` via a provider-injected fixed-origin XRPC requester.
3. Enforce correct status, content type and strict JSON/CAR size budgets;
   disallow redirects and reject unexpected repository or hosting status.
4. Verify the independently returned CAR's DAG-CBOR, current secp256k1
   signature, exact DID, v3 commit CID, revision and non-null MST root.
   This first signup gate deliberately expects a **new empty genesis
   repository**; signed nonempty records are tested in the separate PDS
   writer integration and are not a substitute for genesis acceptance.
5. Reverify the trusted provider signed-head and protected projection after
   all HTTP requests. Return evidence only, not an OAuth token or ready
   permission.

The approved-app and app-client scope is bound by the provider constructor,
not supplied from a public client as account authority. The post-seal
verifier returns the fields required by the previously merged
`createDisposableSignupCompletion` v4 PostgreSQL transaction. That
transaction locks the exact account, signup journal, signed head,
projection, native outbox and canonical app grant in a single COMMIT.
A concurrent grant revocation cannot transform stale evidence into ready.

## Real disposable integration evidence

The acceptance test provisions ONE synthetic new-account ledger operation
inside PostgreSQL 18, signs a genuine genesis CAR under a temporary secp256k1
key, persists the signed head + native event + recovery intent, and
projects the verified head to a mock protected Solid binding. A local XRPC
HTTP server serves the signed CAR and hosting status. The test rejects
corrupt CAR, stale latest-commit responses, relocated/inactive hosting and
invalid approved-app scope, seals the initial reconciliation evidence,
and proves that the post-seal verifier can perform the v4 atomic completion
without minting a second DID or skipping a consent epoch.

All synthetic tables and PostgreSQL roles are deleted afterward; the
temporary account never exists on a public PDS.

## Production NO-GO conditions

- The XRPC probe's loopback requester is **not** a production HTTPS/TLS
  or DNS/egress implementation. A production adapter needs fixed trusted
  PDS origin, SSRF and DNS-rebinding protection, redirects disabled, bounded
  requests, content-type enforcement, deadlines and circuit breaking.
- Solid/account and canonical PG decisions must use deployed least-
  privileged provider connections with **real** distributed SAI consent,
  owner authorization, OIDC/DPoP and protected Jena generation-CAS. The CI
  Solid callback is a fixture, and generic Fuseki writers must never be
  able to mutate canonical permission.
- A production provider must expose complete functioning ATProto PDS
  endpoints, owner sessions/OAuth, record XRPC and blob handling, signed
  history, public sync and event replay, and safe key rotation/migration.
- Complete end-to-end 1/2/4/8 replica recovery with node kill, PostgreSQL
  failover and unknown COMMIT outcomes, simultaneous revoke, key rotation,
  backups/PITR, p95/p99 latency, RSS, broker lag and measured cost.
- No `auth.signup` / `unified-account-api.create` guard or
  `NATIVE_PROTECTED_STORAGE_RELEASED=false` fuse is modified by this
  work. Registration remains NO-GO until independently accepted.

Technical references: https://atproto.com/specs/sync,
https://atproto.com/specs/repository,
https://atproto.com/specs/account.
