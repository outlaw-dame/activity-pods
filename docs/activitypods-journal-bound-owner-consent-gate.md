# ActivityPods / Paper — journal-bound native SAI production gate

**Gate status:** implementation candidate, **NOT RELEASED**. The production
new-account/signup fuse and protected-storage release remain closed. Existing
accounts and ATProto migration are out of scope.

## Invariants

1. One canonical new-account authority: `paper_account_candidate.accounts`
   plus its `signup_operations` row in PostgreSQL 18. The separately signed
   repository and native Solid/Jena representation are durable dependencies,
   not second login or identity authorities.
2. A provider-issued, owner-confirmed HTTPS browser enrollment session is
   claimed once in the existing v6 journal. The opt-in restricted issuer
   receives only the **server-derived 32-byte HttpOnly session-token hash**,
   fixed provider origin and fixed browser origin; it never receives a
   browser-selected owner, DID, reservation, SQL fence or application rights.
3. SQL `begin_session_owner_consent` resolves the session to the existing
   cryptographically bridged v4 reservation/journal, current managed DID,
   canonical WebID, app ID and approved requirements. It verifies the exact
   original approved-app hash and mandatory Paper rights:
   `CreateGroup`, `ReadGroups`, `ManageMembers`. Unexpected or
   misclassified rights deny. It stores a **pending, revision-one** consent
   scoped to the immutable operation and digest. Pending authorizes neither
   signing nor PDS durable publication.
4. Only after pending CAS may the authenticated Pod-owner native
   `auth-agent.registerApp` mutation execute. A crash, timeout or lost
   acknowledgement leaves the v6 enrollment claimed, never replays the native
   mutation, and requires explicit reconciliation.
5. The native registration URI must be recorded in the **same** signup
   journal before attestation. An independent protected-Jena read-only
   principal verifies exact owner, app, access-need group, registration,
   grant and mandatory special rights. Only the attestor SQL login may
   transition pending → active and confirm it against the unchanged
   operation/request fingerprint.
6. Every signing, refresh-token admission and repository mutation still
   rechecks current canonical PostgreSQL consent and revision; an attested
   receipt is only *evidence*, not a long-lived permission token.
7. Owner revocation increments the PostgreSQL epoch and irreversibly blocks
   this initial consent even if Jena still contains an old grant. Revival
   requires a future separately designed, authenticated **new** operation.
   Never reuse a blocked row or relabel a failed operation as ready.

## Restricted credentials and deployment prerequisites

- The ordinary provider, SemApps, Jena projector and public browser cannot
  SELECT or mutate the canonical consent tables or invoke consent functions.
- `paper_atproto_consent_issuer` and
  `paper_atproto_consent_attestor` are **NOLOGIN**, narrow EXECUTE-only
  roles. Provision separate restricted LOGINs; each must have exactly one
  inherited role, no SET/ADMIN privileges, no direct relation DML, no
  schema CREATE and no other authority role.
- The issuer must have EXECUTE **only** on
  `begin_session_owner_consent(text,text,bytea)`. The v2 unbound
  `begin_owner_consent`, v3 raw
  `begin_bound_owner_consent(uuid,uuid)`, and attestation functions are
  deliberately unavailable to the issuer.
- The attestor must have EXECUTE **only** on
  `attest_bound_owner_consent` and
  `confirm_bound_owner_consent`, not issuer or legacy unbound entrypoints.
- Privilege admission and side-effecting SQL use the **same borrowed PG
  connection**. A changed connection or role must be readmitted before the
  first mutation. The attestor keeps its same admitted session while reading
  independently protected native RDF, performing the CAS, reading RDF
  again and confirming the current PG grant. Bounded connection acquisition,
  query timeouts and fail-closed error handling apply. No blind retries
  of ambiguous native or SQL writes.
- The local browser provider runtime optionally wires the independently
  credentialed issuer via `PAPER_JOURNAL_BOUND_SAI_DISPOSABLE=confirmed`
  only with a dedicated `paper_atproto_consent_issuer_login` and an extra
  password in its owner-private configuration. Without the flag the
  existing five-role provider configuration is unchanged. This is **NOT**
  an operator instruction to enable the flag in production.
- This candidate does **not** install a hosted isolated protected-Jena
  attestor service, deploy a real issuer sidecar, apply production migrations,
  or enable positive production signup.

## Implementation and acceptance locations

- `pod-provider/backend/sql/paper-atproto-canonical-authority-v3-bound-enrollment.sql`:
  exact session/journal/reservation mapping, approval scope and CAS,
  plus legacy role revocation.
- `pod-provider/backend/candidates/journal-bound-consent-issuer.js`:
  fixed-scope session → pending issuer with one borrowed PG session.
- `pod-provider/backend/candidates/provider-browser-enrollment.js`:
  after-claim/pre-native pending admission; never retry ambiguous writes.
- `pod-provider/backend/candidates/local-browser-provider-runtime.js`:
  test-only actual provider construction with separate issuer LOGIN.
- `pod-provider/backend/candidates/atproto-signed-repo-proof/journal-bound-sai-pg-attestor.mjs`:
  real protected-Jena typed readback and same-session PG attest/confirm.
- `pod-provider/backend/candidates/atproto-signed-repo-proof/pg-journal-bound-sai-live.mjs`:
  actual PG18 account v1-v6, reservation v4, identity v1-v3 and either
  fixture receipt or independent real Jena  TDB2 readback.
- `.github/workflows/paper-atproto-signed-repo-proof.yml`,
  `.github/workflows/paper-atproto-fuseki-isolation-proof.yml`,
  `.github/workflows/provider-browser-enrollment.yml`:
  independent PG18, Jena restart/recovery, role and owner-browser tests.

The test fixture creates unique synthetic accounts/roles, refuses occupied
schemas, and removes generated credentials and data. A successful test does
**not** imply a production PDS or real exposed user exists.

## Outstanding production acceptance

1. Deploy the separately privileged PostgreSQL issuer service and protected
   Jena attestor with TLS/isolated network, secret rotation, audited
   migrations, immutable app policy and a reviewed real owner journal
   binding. Verify the local provider's optional integration in a
   deployment-equivalent **positive** end-to-end profile.
2. Complete hosted signed ATProto PDS lifecycle for a genuinely created,
   unified new account: PLC DID/handle/key ownership, signed non-empty
   record/repository writes, remote XRPC readback, durable outbox,
   independent recovery and repo-key rotation. Verify normal AP actor
   delivery and Solid login independent of Paper consent.
3. Prove permission revocation and reauthorization across every PDS signing
   path, existing Paper browser sessions, `offline_access` refresh,
   protected SAI RDF and other mobile clients. Simulate replicas, reordered
   events, ambiguous writes, process kills, DB and TDB2 restore epochs,
   partial network partitions and credential expiry.
4. Validate backups, failover and role drift in production-like staging,
   resource/latency/concurrency limits, metrics and cost envelope,
   privacy/sanitized logging, key custody, rollout/rollback and
   independent security review.
5. Only after every positive and negative acceptance criterion is green
   at the **exact reviewed source SHA**, stage and review the separate
   production activation release. Do not quietly lift source-controlled
   `UNIFIED_ACCOUNT_RELEASE_GATE_CLOSED` protections in this PR.

## Handoff checklist

Record the source SHA, PostgreSQL/Fuseki/PDS image digests, fixture and
non-fixture tests, reviewer findings and exact CI run URLs. Inspect PR #256
for the current candidate and the two authoritative repositories only:
`outlaw-dame/activity-pods` (account owner) and
`outlaw-dame/mastopod-federation-architecture` (federation/staging).
Preserve the staging source lock until this PR is merged and its
production-mode **negative-release** deployment check has passed.


## OAuth / PDS credential generation hardening (PR #257 candidate)

**Nonactivated security integration.** This change does not deploy a signed
production PDS or open either new-account signup fuse. It hardens the OAuth
credential lifecycle for existing candidate owner-consent and PDS flows.

- The owner-approved OAuth consent has a random 192-bit generation
  (\`grantId\`). The owner/client consent key is a domain-separated SHA-256
  of the exact URL pair, not a colon-concatenated string, preventing URL
  delimiter collisions and avoiding WebIDs in key listings.
- Authorization codes are issued with the exact generation and atomically
  consumed once using Redis 8.2 \`GETDEL\`. Old pre-generation codes are
  intentionally denied. A code consumed after its owner's revoke/reapprove
  can no longer mint tokens on the old generation.
- Access JWTs carry \`consent_grant_id\`. Actual provider
  \`oauth-token.introspectAccessToken\` and issuance reread the current
  consent. Only a matching active owner/client/scope/grant is valid. Paper's
  PDS DPoP bridge checks the same generation before and after signed writes.
  A fresh reapproval never reactivates an old signed JWT.
- Refresh-token issue and rotation use atomic Redis scripts to check the
  same current generation, DPoP key, revocation marker, encrypted previous
  record and bounded family size. Exactly one competing rotation succeeds.
  A competing replay marks the family revoked so even the apparent winner's
  successor is denied.
- A refresh-family revocation writes a durable marker in O(1) instead of
  decrypting/updating every family token. Index size is capped at 512 and
  tokens expire under configured TTLs. Exhausting the cap requires a new
  owner authorization, not silent pruning of live token identifiers.
- Redis services now await connection readiness before accepting commands.
  Offline command queuing and automatic resend of unacknowledged operations
  are disabled. Lost command ACKs fail closed. A unique private 32-byte
  refresh AES-GCM key is required at production service startup; the
  historical example key is rejected.
- Live disposable Redis 8.2 tests:
  \`pod-provider/backend/scripts/proof-oauth-consent-refresh-redis.js\`
  and \`proof-provider-pds-oauth.js\`, run by
  \`.github/workflows/paper-oauth-consent-epoch-proof.yml\`.
  Include two independent connections, code double-redeem, stale JWT and
  code after reapproval, refresh CAS/replay/revocation, family capacity,
  signed DPoP, nonce replay and key-configuration denials.

**Important remaining risks and deployment tasks:** Redis restoration could
roll back a revocation or grant generation without a separate durable
PostgreSQL restore epoch. Before enabling production, implement and test a
restore-aware token-epoch fence across PostgreSQL and Redis and prove
replica failover/recovery, rotation-key migration, maximum TTL behavior and
OIDC-provider (Solid-OIDC) session/grant revocation for Paper independently.
Run positive hosted PDS signed-write, real new-account signup and independent
security review; none is established by this disposable proof. Promotion of
legacy unversioned credentials is prohibited: affected clients must
reauthorize with owner consent. Record reviewed CI and source SHA before
considering any release change.


## Staging-derived OAuth service loader hardening (PR #258)

The post-#257 **production-mode staging** provider initially failed startup
because the new Redis Lua refresh-policy helper was stored under
`backend/services/oauth/`. Moleculer's configured recursive service glob
`services/!(utils)/**/*.js` tries to register any JavaScript file there as
a service. The helper exports algorithms, not a Moleculer service schema.
It belongs at `backend/utils/oauth-refresh-atomic-policy.js`, outside that
loader namespace. Its imports are explicit in the three consuming modules.
The Redis OAuth workflow now rejects any non-`*.service.js` JavaScript file
under `backend/services/oauth/` before integration testing. This failure
was **not** detected by isolated real-Redis tests; the full production-mode
staging provider-startup test is an independent mandatory acceptance check.
The private AES key stays required, and no signup/SAI/PDS release fuse changes.

## OAuth front-channel single-use race hardening (2026-11-21 candidate)

The existing PAR and owner consent-challenge implementations used Redis
GET followed by DEL. On separate provider replicas, both callers could read
the same one-time record before either deletion. The new implementation
uses atomic Redis 8.2 GETDEL for both consumption paths, matching
authorization-code and DPoP nonce behavior.

PAR, consent-challenge and DPoP nonce services now refuse offline command
queueing and auto-resend of unacknowledged Redis commands. Startup requires
Redis connection readiness and PONG. PAR/challenge/nonce creation requires
an explicit OK acknowledgment before returning a browser-useable value.
An unknown GETDEL acknowledgment is a *burned/uncertain* request:
never retry it blindly, fail closed and issue a fresh owner-authenticated
authorization interaction instead.

`pod-provider/backend/scripts/proof-oauth-frontchannel-single-use-redis.js`
runs against actual Redis 8.2 through two separate clients, verifies
at most one winner for PAR, consent challenge and DPoP nonce, and
deterministically forbids the previous GET + DEL implementation. The
workflow checks the test script and all three service modules, and runs
the existing OAuth refresh/DPoP acceptance independently.

This is a nonactivated security hardening gate. It does not provide the
outstanding PostgreSQL restore-epoch fence, protected owner SAI
deployment, hosted PDS, or positive production signup readiness.
