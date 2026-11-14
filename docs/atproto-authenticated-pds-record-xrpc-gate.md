# ActivityPods hosted PDS authenticated record-write gate

**Status: NON-ACTIVATED, DISPOSABLE INTEGRATION ONLY. Production signup,
PDS HTTP routing and native protected storage release fuses remain closed.**

## Why this gate

ActivityPods already owns the new unified-account WebID = ActivityPub actor,
managed DID/PLC identity and signing keys. The existing signed PostgreSQL
repository and upstream `@atproto/repo` MST writer can create immutable
signed commits, while read-only Sync XRPC can export a verified CAR. They
were not connected to an authenticated record-write HTTP boundary.

This gate deliberately uses the existing `reference-mst-writer.mjs` and
`paper_atproto_repo_proof` tables, without creating another account
registry, repository implementation, signing key or event queue.

## Implemented nonactivated behavior

- HTTP `POST` support for the **subset** of the official
  `com.atproto.repo.createRecord`, `putRecord`, `deleteRecord` lexicons.
  Unlike unrestricted ATProto requests, the candidate *requires* a caller
  record key and `swapCommit` to provide explicit CAS/idempotency. The
  `validate:false` option and unknown fields are rejected, and full
  lexicon validation is not yet implemented. The candidate does not claim
  complete standard PDS coverage.
- A verified, local ActivityPods-managed DID, current provider PDS HTTPS
  origin, same WebID/AP actor and active hosting status are required.
  A client cannot choose the backend WebID, signing key, grant, app scope
  or arbitrary endpoint. HTTP bodies are capped at 96 KiB and invalid
  methods/content types fail closed.
- The trusted provider callback must verify OAuth, issuer, audience,
  DPoP and the current account/app/SAI authorization. The HTTP module does
  not parse or trust client JWT fields, is not exposed through the normal
  API gateway, and cannot run when `NODE_ENV=production`. **The test
  injects a synthetic provider verdict; it is not real OAuth/DPoP proof.**
- The writer re-verifies the signed PostgreSQL commit/MST and record CID.
  A pre-signature authorization check is necessary but insufficient:
  the newly injected `lockCanonicalConsent` callback executes **on the
  exact same PostgreSQL client/transaction** as the signed-head CAS,
  immutable blocks, native event outbox and RDF projection intent.
  `FOR SHARE` on canonical identity/consent serializes with the
  `block_consent` UPDATE; an acknowledged revocation cannot be skipped
  between the last authorization check and repository commit.
- The HTTPS response is 200 only after the protected projected state
  matches the new head, hosting is unchanged, OAuth/app consent is checked
  again, and the new signed PostgreSQL head agrees. An uncertain projection
  or a revocation after commit yields a generic 503. It is **not**
  permission to retry the write behind the existing swapCommit.
- Signed repository history and native event outbox commit atomically
  under the previously proven writer. Events remain PG-owned until the
  separately tested Redpanda publisher is enabled as part of the provider
  deployment.

## Exact-head disposable acceptance

The new PostgreSQL 18 test bootstraps a genuine secp256k1-signed v3 CAR,
uses the independently pinned upstream `@atproto/repo` MST,
creates canonical PG identity/SAI grant, and runs real local HTTP
create/put/delete against the existing writer. It checks OAuth failures,
foreign DID, stale swapCommit, signed-head and outbox persistence, projection
readback, current Sync XRPC, deletion, revocation, and production refusal.
It tests the SQL role-lock path against real PostgreSQL rather than trusting
a Boolean from the writer.

## Production blockers — remain NO-GO

1. Register **one** reviewed ActivityPods-managed new-account coordinator
   using the merged PostgreSQL v4 atomic completion; do not register stacked
   #134/#140 directly or retain a parallel PLC genesis writer.
2. Replace synthetic OAuth/DPoP and projection callbacks with actual trusted
   Solid-OIDC and ATProto OAuth authorization, including revocation-proof
   distributed consent epochs, key custody and identity/hosting
   reconciliation. A 'verified' flag from caller input is never evidence.
3. Provide real protected Fuseki per-Pod atomic monotone CAS, SQL least-
   privileged login roles for signed repo write + canonical grant locks,
   and final HTTP-edge grant fencing under multi-cell outages. General
   SPARQL writers must not mutate canonical PostgreSQL authorization.
4. Complete broader PDS behavior: proper createRecord key allocation,
   lexicon validation and record constraints, authenticated record
   reads/listing/put/delete/applyWrites, blob upload/export, sessions,
   DID/handle/domain hosting, stream subscription, relay acceptance,
   migration and recovery. The current single XRPC route is an acceptance
   candidate, not a production-complete PDS.
5. Prove real HTTPS reverse proxy, rate limits, size budgets, OAuth/DPoP,
   record signing and public CAR from independent clients, native event
   delivery/replay, node kills, uncertain DB commits and backups on
   deployed infrastructure. Measure sustained throughput, p95/p99,
   bounded RSS, broker lag, retries and cost.
6. Keep the release fuse source-controlled and closed until all necessary
   criteria are independently accepted. Legacy accounts are unaffected.

Reference sources:
- https://atproto.com/specs/xrpc
- https://atproto.com/specs/repository
- https://atproto.com/specs/sync
- https://github.com/bluesky-social/atproto/tree/main/lexicons/com/atproto/repo
