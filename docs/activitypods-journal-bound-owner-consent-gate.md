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

## OAuth owner browser-session cookie hardening (2026-11-21 candidate)

The login/authorization HTTP service previously accepted the fixed
`dev-oauth-session-secret` HMAC fallback even when `NODE_ENV=production`
if both `OAUTH_SESSION_SECRET` and `ACTIVITYPODS_TOKEN` were unset.
This would permit forging a WebID-bearing owner browser session and is
a **production authentication boundary**, not a cosmetic cookie concern.
The provider now fails startup in production unless the configured
session-signing secret is private and at least 32 UTF-8 bytes. Staging
already provisions a unique owner-private `ACTIVITYPODS_TOKEN`.

In addition, malformed attacker-controlled cookies previously could raise
uncaught `URIError` during `decodeURIComponent` or a length exception
during `crypto.timingSafeEqual`. The cookie parser now skips malformed
values; the owner-session verifier requires an exactly two-part token with
a bounded length and a 43-character SHA-256 base64url MAC before its
constant-time comparison. The cookie parser uses a no-prototype key map.
Invalid cookies always yield absent user authentication rather than
unhandled exceptions or partial approvals.

`pod-provider/backend/scripts/proof-oauth-session-cookie-boundary.js`
proves a legitimate session roundtrip, malformed and oversized signatures,
appended token segments, malformed URI percent encodings, valid sessions
alongside unrelated invalid cookies, and missing/weak production secret
startup denials. The pinned OAuth proof workflow runs this offline
test plus all live Redis consent/refresh and signed PDS OAuth checks.
This remains nonactivated; owner-consented positive production signup
and the restore-aware PostgreSQL/OAuth generation fence remain closed.

## PostgreSQL OAuth restore fence — candidate gate (November 21, 2026)

**Not activated; production signup remains CLOSED.** The existing OAuth
generation/refresh/DPoP guards are Redis-backed. Restoring a pre-revocation
Redis snapshot can restore a credential already rejected before recovery.
The separate canonical native-SAI PostgreSQL consent authority can stop
this class of resurrection, but the OAuth grant ID must be bound to PG.

- `pod-provider/backend/sql/paper-atproto-canonical-authority-v4-oauth-generations.sql`
  defines the smallest necessary OAuth credential-generation projection
  **inside the existing canonical `paper_atproto_authority` schema**,
  keyed by owner WebID and OAuth client. It does not create a new account,
  DID, Pod, or identity authority. It references the canonical owner/app
  SAI grant, accepts only a previously independently attested native
  consent, and ties every credential generation to the current SAI
  revision and scope digest. Generation IDs are unique and never
  reissued at the same revision. The subordinate OAuth rows cascade on a
  deleted native SAI consent, avoiding a new blocker to owner erasure;
  credential verification then necessarily denies the missing grant.
- Separate NOLOGIN issuer, revoker, reader and signer roles have only
  function EXECUTE. The new table is inaccessible to the provider,
  ordinary Jena/SPARQL users, or the unauthenticated public. No runtime
  LOGIN is provisioned by this candidate.
- SQL `issue_oauth_generation` performs a revision CAS and locks native
  SAI consent; `revoke_oauth_generation` permanently bumps the epoch
  via CAS; `verify_oauth_generation` rejects any stale Redis generation,
  mismatched scope, revoked native consent, or blocked local identity.
  The `lock_oauth_generation_for_write` predicate must execute in
  the **same PostgreSQL transaction** as a signed PDS repository write;
  row locks serialize an acknowledged OAuth/native revocation against
  already-admitted writes. A separate preflight SELECT is insufficient.
- `pod-provider/backend/scripts/proof-oauth-pg-restore-fence.mjs`
  and `.github/workflows/paper-oauth-pg-restore-fence.yml` exercise
  disposable PostgreSQL 18 + Redis 8.2, two competing issuers, two
  revokers, least-privilege SQL roles, signed-write lock contention,
  an intentionally restored pre-revocation Redis grant and native
  SAI revocation. Existing v1/v2 activation is a synthetic fixture;
  the genuine v3 session journal and protected Jena attestation remain
  independently enforced elsewhere.

**Unresolved, do not activate:** OAuth authorization currently writes
Redis generations without a trusted owner-journal-bound PG issuance call;
JWT/refresh tokens do not yet carry the PG epoch, and the PDS writer is
not wired to the transaction-local signer predicate. Neither endpoint
must be treated as protected by this candidate until all are updated
together and rechecked against real primary PG on every signing path.
No reader replica with possible stale grants may authorize writes.

**PostgreSQL PITR rollback:** An independent non-rewindable recovery
witness/high-water outside both backed-up PG and Redis is mandatory.
A PG backup restored from before revocation can otherwise resurrect
both PG and Redis state. This proof only demonstrates that PG surviving
a **Redis-only** rollback remains authoritative. Require operator recovery
with an externally monotonic witness, restore/failover integration, exact
owner-bound consent, service-key rotation and standalone hosted PDS
acceptance before enabling any production OAuth generation issuer.
See federation tracking issue #186. Never treat a passing Redis/PG
fixture test as a production recovery signoff.

## OAuth read-side integration candidate — still NOT ACTIVATED

This gate extends the prior PG18 v4 control-plane candidate with
pod-provider/backend/sql/paper-atproto-canonical-authority-v5-oauth-current.sql.
The new SECURITY DEFINER current-epoch function returns a revision only if
the specified OAuth grant ID, scope digest, owner WebID, app mapping,
managed identity, and independently attested native SAI revision agree.
It gives only the restricted OAuth reader role EXECUTE; neither the
issuer nor the reader can directly SELECT the authority table.

pod-provider/backend/candidates/oauth-pg-epoch-reader.js tests this
function through a real isolated PostgreSQL LOGIN with re-audited role
membership, function EXECUTE privileges, direct-table denials and
a server-configured exact client-ID to native SAI application mapping.
The browser never supplies or chooses the SAI application URI.

The actual oauth-code-store, oauth-token and oauth-refresh-session
handlers now have a disposable test-only PG admission boundary in
backend/utils/oauth-pg-epoch-policy.js:
- Fresh authorization codes carry the PG revision; old/missing-epoch
  codes cannot exchange for signed credentials while the candidate is on.
- Signed access JWTs include oauth_pg_revision; introspection checks
  the live Redis consent, exact signed epoch and fresh PG state.
- Newly encrypted refresh-token families contain the exact epoch,
  and issuance/rotation/introspection checks a fresh PG decision.
  If PG is unavailable, missing, restored behind the expected
  generation or lacks attested native SAI approval, the action fails
  closed rather than trusting a restored Redis snapshot.
- The existing PDS bridge calls real JWT introspection on initial
  authorization and again before each write, so it inherits this
  read-side fence. The PG write-time lock is not wired to the actual
  signed-repository commit yet.

These code paths are callable only when ALL of NODE_ENV=test,
PAPER_OAUTH_PG_EPOCH_DISPOSABLE=confirmed,
PAPER_OAUTH_PG_RESTORE_DISPOSABLE=confirmed, and
PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE=confirmed are set. If the
candidate flag is set outside this fixture context it rejects
authorization; without it the existing release-closed OAuth behavior
is unchanged. No production issuer/reader credential is provisioned.
This is NOT an authorization to enable new production signups.

The disposable PG18+Redis 8.2 CI proof now invokes the real
authorization-code exchange, signed JWT issuance/introspection, encrypted
refresh issue/introspection/rotation, PG reader role admission and
Redis binary DUMP/RESTORE after an owner revocation. It separately
tests new PG reapproval, a stale pre-revocation authorization code,
and deletion of the native SAI grant. Existing default-mode
OAuth/DPoP proofs still run with the candidate disabled.

STILL BLOCKING RELEASE: The owner-authenticated issuer and revoker
are not wired to a live browser coordinator, PG epoch/Redis upsert and
native SAI consent are not yet atomically coordinated, the real PDS
writer must acquire the PG revision lock in its commit transaction,
and independent monotonic recovery authority across PostgreSQL PITR
is absent. An actual multi-cell provider and signed PDS positive
signup, restorable backup, and failover acceptance must precede
any production activation. See federation issue #186.
