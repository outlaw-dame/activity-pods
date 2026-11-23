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
