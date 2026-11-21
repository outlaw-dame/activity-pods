# ActivityPods: owner signup journal -> native SAI -> canonical PG activation

**Status: NONACTIVATED candidate. Production signup and protected storage
release remain CLOSED.** This gate concerns NEW unified accounts, not
migration of existing ActivityPub, Solid, or external ATProto accounts.

## Canonical authority path

1. ActivityPods's existing PostgreSQL account and signup journal supplies the
   sole provider identity: WebID / ActivityPub actor and managed ATProto DID.
   The preaccount coordinator reservation is linked to the canonical journal
   by an exact v4 bridge, immutable request HMAC and approved-app SHA256 scope.
2. Owner browser consent uses a Secure, HttpOnly, short-lived enrollment
   cookie and CSRF protection. The account journal irreversibly records
   consent_claimed with owner-chosen required and optional rights BEFORE any
   native SemApps SAI mutation.
3. A separate issuer PostgreSQL LOGIN sees only a SHA256 enrollment-session
   token, fixed provider origin and app origin, never a browser-supplied WebID,
   DID, reservation, application, approval boolean or permission set.
   Its SECURITY DEFINER admission resolves the owner-claimed token to the
   existing journal and reservation. The issuer can only reserve PENDING
   consent and cannot execute old unbound functions or direct table DML.
4. The browser route refuses to invoke native SAI on a missing, false or
   ambiguous canonical issuer result. The irreversible consent_claimed state
   remains for explicit reconciliation, never an automatic replay.
5. Only after the pending SQL authority is durable does ActivityPods call
   native SAI registerApp exactly once. The persisted enrollment registration
   URI is checked against an independently read native ApplicationRegistration,
   AccessGrant, grantedBy, grantee, access-need group and all of Paper's
   mandatory CreateGroup, ReadGroups and ManageMembers permissions.
6. The independently credentialed, read-only Jena attestor calls the
   journal-bound PostgreSQL attestation function, reads Jena again and
   confirms the *current* canonical SQL grant. Any altered owner, DID,
   registration, manifest, optional/required selection, proof or consent
   revision denies. Revocation is permanently monotonic.
7. Attestation is EVIDENCE ONLY, never a long-lived permission token or an
   atomic PostgreSQL/Jena snapshot. Every later PDS write, projection
   ticket and client authorization must recheck current PostgreSQL consent
   and the signed repository head.

## Implementation and tests

- Migration: pod-provider/backend/sql/
  paper-atproto-canonical-authority-v3-bound-enrollment.sql
  (additive and nonactivated; it replaces the issuer's unbound v2 EXECUTE).
- Browser order: pod-provider/backend/candidates/
  provider-browser-enrollment.js (opt-in test-only pending PG reservation
  after owner claim and before native registerApp).
- Restricted issuer: pod-provider/backend/candidates/
  journal-bound-consent-issuer.js (exact PostgreSQL 18 role and one borrowed
  connection across privilege audit and conditional grant).
- Restricted attestor: pod-provider/backend/candidates/
  atproto-signed-repo-proof/journal-bound-sai-pg-attestor.mjs
  (read-only protected Jena, typed RDF, conditional SQL attestation and
  current SQL confirmation).
- Real PG18 fixture: pg-journal-bound-sai-live.mjs; uses existing account
  v1-v4/v6, v4 preaccount reservation bridge, managed DID and consent v1-v3.
  Rejects unclaimed enrollment, wrong app hash/session/origin, missing
  mandatory permission, forged registration, changed manifest and approval,
  older proof/revision, unsafe SQL role, duplicate operations and concurrent
  independent revocations.
- Real isolated Fuseki/TDB2 proof: paper-atproto-fuseki-isolation-proof.yml;
  independent Jena projector and reader credentials, native registration,
  verified rights and PostgreSQL activation under restricted logins.
- Actual provider browser HTTP and Chromium paths:
  provider-browser-enrollment-node.test.cjs and provider-browser-enrollment.yml.
  A bounded issuer refusal cannot trigger native registration or a replay.
- Preserve existing exact-head signed repository, canonical coordinator,
  local signed PLC, backend, lint and protected storage workflows.

## Remaining real production blockers

This gate does NOT deploy the actual production coordinator issuer, protected
SAI migration/attestor or externally hosted PDS. A positive authenticated
new-account end-to-end deployment test, live signed non-empty repository,
external DID/handle/XRPC verification, permanent revocation of preexisting
OIDC and refresh tokens, cross-replica crash/reconciliation, backups and
restore epoch, performance/memory/cost review, updated supported Jena
runtime, independent security review and operator release approval remain
necessary. The production signup fuse must stay CLOSED until all conditions
are independently proven.

## Handoff

Track ActivityPods PR #256. Record its verified head, GitHub CI results and
merged master SHA; never promote this candidate based on a synthetic proof.
Only after merge, update the federation repository's immutable
deploy/paper-staging/lock.json ActivityPods pin in a separate tested PR,
preserving frozen federation source, container digests and release=CLOSED.
Never log session cookies, passwords, private keys or owner profiles.
