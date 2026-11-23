# Paper unified-account canonical credential revocation gate

**Status: NONACTIVATED, security-critical candidate. Production release CLOSED.**
This is for **new unified accounts**, not a silent migration of legacy accounts.

## Verified upstream behavior and the gap

In pinned SemApps `@semapps/auth` (1.1.4) the `AuthLocalService`
creates an `auth.jwt` service, which signs arbitrary `payload` with
RS256. The upstream signer does **not set a mandatory expiration**.
Both `auth.authenticate` and `auth.authorize` call
`auth.jwt.verifyServerSignedToken`. The upstream verifier only checks
RS256 validity, not current password or owner epoch. Password changes
occur through `auth.account.setPassword`, `setNewPassword`,
`updateAccountSettings` (when newPassword is present), as well as
account removal/tombstoning.

Sources:
- https://github.com/assemblee-virtuelle/semapps/blob/master/src/middleware/packages/auth/services/jwt.ts
- https://github.com/assemblee-virtuelle/semapps/blob/master/src/middleware/packages/auth/mixins/auth.ts
- https://github.com/assemblee-virtuelle/semapps/blob/master/src/middleware/packages/auth/services/account.ts
- https://github.com/assemblee-virtuelle/semapps/blob/master/src/middleware/packages/auth/services/auth.local.ts

The existing Paper `AccountEnrollmentMiddleware` already intercepts
the same two JWT actions and checks that the WebID belongs to an
existing account, but it does not revoke a previously issued, correctly
signed token after a password change. The newer Paper DPoP access
tokens independently verify owner consent and PostgreSQL epoch; these
are a distinct token class and do not fix the legacy RS256 route.

## New isolated prototype

`pod-provider/backend/middlewares/credential-epoch.js` exposes:

- `createDisposableCredentialEpochMiddleware`: wraps only
  `auth.jwt.generateServerSignedToken` and
  `auth.jwt.verifyServerSignedToken` through Moleculer localAction.
  The original SemApps RS256 signature verification must still succeed.
  New unified-account JWTs carry an independently sourced
  `paper_credential_epoch`, and bounded `iat`/`exp` (15 minutes
  by default), all under the original signature. The verifier rejects
  old no-exp JWTs for unified owners and checks the current authority
  on every read, **without a positive cache**.
- `runDisposableCredentialChange`: proof-only coordinator. An
  authority must atomically change the owner to a `pending` state
  before any password/account write. Token admission denies while
  pending. After an *acknowledged* account write it seals a new
  credential epoch. Unknown mutation/ACK or sealing outcomes remain
  fenced and require operator reconciliation, not automatic replay or
  rollback. Missing authoritative responses fail closed.
- Owner classification is itself read from the canonical independent
  authority, rather than relying solely on a restored account's
  `signupReservationId` marker. Missing marker plus unified owner, or
  marker plus legacy owner, fails as an unsafe downgrade. Previously
  un-migrated legacy accounts are excluded from the new behavior in
  this disposal-only proof.

The module has hard runtime gating requiring
`NODE_ENV=test`, `PAPER_CREDENTIAL_EPOCH_DISPOSABLE=confirmed`, and
`fixtureOnly=true`. It is deliberately **not registered** in
`moleculer.config.js`; a memory-backed fake epoch is not a real
credential revocation authority.

## Threat and failure tests

`pod-provider/backend/scripts/proof-paper-credential-epoch.cjs` uses
actual RS256 sign/verify operations and disposable account and
authority fixtures. It tests issuance/expiry, stale credentials,
authority outage and pending mutation refusal, credential generation
rotation, ambiguous account writes, concurrently signed tokens, legacy
isolation, forged/missing metadata, and restoration-induced account
classification downgrades.

Run after backend dependencies are installed:
```sh
NODE_ENV=test PAPER_CREDENTIAL_EPOCH_DISPOSABLE=confirmed \
  node --test pod-provider/backend/scripts/proof-paper-credential-epoch.cjs
```

## Remaining production P0: do NOT treat this prototype as acceptance

A real canonical, independently rollback-resistant **owner credential
epoch authority** must be specified and deployed with a nonrewindable
latest head. The following operations MUST be joined to the same
serialized transaction/fence: password reset, authenticated password
change, direct password set, account disable/deletion/tombstone,
WebID ownership rotation and relevant session-wide logout. It must
cover *every* path that changes credentials, including upstream SemApps
actions, administrative changes and storage mutations bypassing
ordinary HTTP routes. Ownership, CSRF, reset-token and current-password
proofs MUST be checked before advancing the epoch; unverified public
password requests must never be able to force logout by rotating
somebody else's epoch. Pending/unknown outcomes need explicit durable
reconciliation, including a crash after the downstream password write.

Issuance and verification must be integrated across the actual
SemApps/ActivityPods broker topology (including remote service cells),
Solid-OIDC/SAI authorizations, native PDS signing/XRPC operations and
all relevant refresh/session token classes. No route may bypass
canonical owner epoch admission. The same authority must detect
restored old primary DB+Redis+Jena+PDS state after a revocation.
Complete tests with real independent PostgreSQL18/WAL/PITR,
HTTP routes, all replicas, replayed bearer tokens, signed PDS writes,
and real external highest acknowledged epoch. An independent human
security review and positive hosted new-account acceptance are still
required.

Never enable this middleware just by changing the test-only
environment switches or clearing signup's production fuse.

## PostgreSQL 18 restricted authority candidate (NONACTIVATED)

The dedicated SQL candidate at
`pod-provider/backend/sql/paper-credential-epoch-authority-v1.sql`
is isolated from the SemApps/Redis/Jena service credentials. It defines
three non-LOGIN roles (reader, enroller, coordinator) and grants **function
execution only**, with no ordinary SELECT/UPDATE/CREATE privileges against
the protected owner table. Function bodies are SECURITY DEFINER with a
fixed pg_catalog search path. It has no background migration, endpoint,
authorization cutover, or deployment configuration.

- Enrollment is create-once and cannot turn a disabled owner into an
  active one. Actual authorized signup/owner proof is a prerequisite and
  is NOT implemented by the SQL function itself.
- Credential mutation first transactionally enters `pending` with a
  UUID and monotonically increasing proposed epoch. While pending,
  every authorization reader must DENY. Wrong operation, old expected
  revision, concurrent begin and duplicate seal fail rather than retry.
- Sealing requires an operation-matched 32-byte downstream mutation
  receipt digest. This enforces shape and identity, not authenticity:
  the service must verify that the digest binds a **committed, authorized**
  SemApps write before invoking seal. Unknown receipt or lost write
  acknowledgement keeps the owner pending.
- Terminal disable monotonically advances epoch and denies re-enrollment.
  None of these operations can be allowed to silently skip the
  independently held signed latest credential checkpoint.
- **PostgreSQL physical backup alone is rewindable**; roles and SQL
  transactions are not a replacement for externally controlled latest
  epoch custody, before/after physical PITR, or the SemApps password
  mutation API integration.

CI: .github/workflows/paper-credential-pg18-authority.yml
runs a pinned real PostgreSQL 18 database and
`pod-provider/backend/scripts/proof-paper-credential-pg18.sh`
with disposable guards. It checks unauthorized direct table reads/writes,
schema writes, function privilege separation, pending/failure refusal,
replay/re-enrollment denial, and terminal disabled state. It MUST stay
nonactivated until the full owner-verified credential mutation service,
distributed read path, independent live custody and recovery tests exist.

## Challenge-bound independent latest credential head (NONACTIVATED)

The v2 candidate strengthens the previous PG18 restricted role proof without
claiming to close the production custody or native-authorization release gate.

- `candidates/credential-signed-latest-head.js` generates 256-bit random
  per-read nonces and requires an Ed25519-signed, domain-separated canonical
  `paper.credential.head.v1` response containing the exact owner hash,
  owner epoch, active/pending/disabled state, mutation receipt digest, nonce,
  trusted authority identifier, and bounded issue time. The pinned public key
  and trusted authority are constructor-only, not HTTP request parameters.
  A previously valid signed response cannot satisfy a new random challenge.
- `sql/paper-credential-epoch-authority-v2-certified-head.sql` grants the
  narrowly privileged reader a function returning the credential state and
  committed mutation digest. General application SQL cannot read or change
  the protected table through this function.
- `candidates/credential-pg-certified-reader.js` verifies a physically
  restricted PostgreSQL18 LOGIN on every call, obtains a fresh independently
  signed head before **and after** its current PG state read, rejects
  mismatches, missing owners, pending/disabled reuse, forged signatures,
  stale replayed responses, and rollback. No positive cache or Redis fallback.
- `scripts/proof-paper-credential-certified-pg18.cjs` and the dedicated
  PostgreSQL18 CI workflow cover these invariants against a *real* restricted
  PG login, signed challenge issuer simulation, concurrent advances, and a
  deliberately rewound owner row.

**Critical security limit:** A nonce proves freshness of the *signature
response*, not the freshness of the signer's own database. The signer must
run outside the Paper deployment/account/control plane, maintain a
nonrewindable latest-head register, and refuse any rollback or signing of an
old epoch. The private Ed25519 signing key must remain solely with its
independent custodian. This disposable proof does not administer the signer,
create independently immutable archive storage, execute physical multi-store
PITR, cover real owner-authenticated SemApps mutation pathways, or give
production admission. No production middleware import or service activation
is permitted. The source-controlled signup fuse remains CLOSED.

The same disposable PG18 proof now composes the existing RS256 credential
middleware with the **actual separate-login PostgreSQL reader** and an
Ed25519-signed nonce-bound head. It verifies old JWT denial while mutation
is pending, after a new epoch is sealed, after a deliberate PostgreSQL row
rewind, and after terminal disable, while a freshly signed new-generation
JWT is accepted only when all authorities agree. The SemApps broker lookup
is still a local fixture; this is not a deployed authenticated password
reset/rotation route or hosted Solid-OIDC/SAI/PDS acceptance.

## Real credential-state physical PostgreSQL recovery acceptance (NONACTIVATED)

The existing two-database physical PostgreSQL18/WAL/PITR proof now loads
the **actual** restricted credential epoch v1 and certified reader v2
SQL into two separate disposable PostgreSQL clusters before the backup.
Each cluster creates a unified owner at epoch 1, takes a full physical
`pg_basebackup` with a verifiable backup manifest, then terminally
disables that owner at epoch 2. Independently archived WAL restores
each cluster at named points on both sides of disablement. The test
asserts `unified:active:1` on each pre-disable physical restore and
`unified:disabled:2` after, and confirms the two independent cluster
system identifiers. A pre-disable snapshot cannot meet an **externally
expected** epoch 2; the expected external head is an explicit
assumption, not a real live independent custodian in this test.

The named restore test is
`pod-provider/backend/scripts/proof-oauth-dual-pg18-physical-pitr.sh`.
It does not exercise a physically restored Jena/Redis/PDS, an actual
independent signing/immutability service, or a hosted cross-protocol
owner-approved signup. The production release gate remains CLOSED.

## Native SemApps PostgreSQL credential mutation enforcement (v3, NONACTIVATED)

The existing \`paper_private_auth.accounts\` table stores the SemApps
\`hashedPassword\` inside its \`data\` JSONB column. Its runtime SQL role
previously had unrestricted \`UPDATE(data)\` and \`DELETE\`. If promoted
unchanged, an attacker with that restricted account writer (or a buggy
account action) could change a unified owner's password *without*
advancing the independent revocation epoch, or remove and recreate a
claimed account. This is a **production-critical bypass**.

\`pod-provider/backend/sql/paper-credential-epoch-authority-v3-native-bcrypt.sql\`
adds narrowly scoped, test-only database enforcement:

1. A SECURITY DEFINER trigger refuses **every direct bcrypt change or
   removal**, unless a matching operation-specific receipt was inserted
   in the *same PostgreSQL transaction*, matches the new hash, and
   corresponds to the exact owner in durable \`pending\` state. It also
   refuses ordinary deletion of a claimed unified account or insertion
   over an already registered credential owner. Ordinary preferences
   updates remain allowed.
2. A separate \`paper_credential_native_writer\` has EXECUTE on
   \`write_native_bcrypt\` only. The function locks the owner epoch and
   native account, requires an exact pending UUID and next revision,
   accepts only encoded bcrypt with work factor 10–14 (the pinned SemApps implementation uses 10; values outside the range are rejected to prevent excessive login work), and atomically writes
   the native bcrypt and SHA-256 receipt to an append-only operation
   table. A lost ACK is reconciled using the operation UUID; it is
   **not automatically retried or rolled back**.
3. A distinct \`paper_credential_native_attestor\` can only call the
   positive readback predicate for the persisted operation and cannot
   enumerate native account hashes, profile data or receipt rows.
4. The general-purpose digest-only \`seal_change\` EXECUTE is REVOKED
   from the coordinator. A separate \`paper_credential_native_sealer\`
   can seal only the exact previously committed native bcrypt receipt.
   After sealing, the independent latest-head read must still match
   before any token is admitted. This local receipt does **not**
   authenticate an owner or constitute independent archival custody.
5. The real PostgreSQL18 CI test uses separate restricted LOGINs,
   denies direct credential edits/owner deletion, tests transactional
   rollback before ACK, wrong operation/epoch/hash, forged seal,
   replay, append-only audit, positive receipt correlation and
   terminal disabled-owner refusal.

**Important:** the v3 SQL is deliberately *not auto-migrated* and the
native writer is not yet wired to the authenticated SemApps password
change/reset handlers. Before production, those handlers must establish
real owner authentication and authorization and atomically reserve a
credential operation; the independently operated latest-head signer
and immutable receipt custodian must attest pending and sealed epochs,
with bounded failure/rollback recovery. Deletion still requires a
separately approved tombstone/erasure policy. Production signup
remains CLOSED. Synthetic bcrypt-shaped strings in the SQL proof are
not a test of bcrypt password hashing: the existing native SemApps
account tests separately cover hashing/comparison.
