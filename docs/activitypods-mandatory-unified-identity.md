# Unified account identity contract — mandatory WebID + ActivityPub + did:plc

**Release status: PR proof; no live data migrated.** This contract applies to
new account creation through the unified-account API and to the legacy
production signup path. It does **not** change existing WebIDs, DIDs,
usernames, PDS repositories or signing keys.

A completed new account must have:

1. A canonical HTTPS **WebID** that is also the **ActivityPub actor ID**.
   The provider's internal account record identifier may remain distinct
   from the public WebID; identity binding must remain unique and durable.
2. A **did:plc** AT Protocol identity (not did:web), with identity mapping,
   generated/managed keys in the existing secure key container and an
   initialized ATProto PDS repository. The ATProto handle is a separate
   mutable identifier, not a replacement for the DID.
3. Existing public actor inbox/outbox/key metadata and WebID/Pod ACL
   bootstrap. A DID alone does not imply a working ATProto account.

The new account API rejects `solid.enabled=false`,
`activitypub.enabled=false`, `atproto.enabled=false`, boolean
`protocols` opt-outs and `atproto.didMethod=web` BEFORE account
provisioning. The unified service enforces the contract again even for
internal calls. If did:plc creation, PDS repo initialization or AP/WebID
binding fails, the request must not be reported as a completed account.
Production legacy `auth.signup` does not honor the older
`APODS_AUTO_PROVISION_ATPROTO_ON_SIGNUP=false` bypass; this remains
usable only by explicitly isolated non-production federation fixtures,
which must never be represented as full account onboarding.

## November 2026 implementation findings and safety fences

The current `accounts.create` delegates to `auth.signup`. That action already
performs the authoritative WebID, ActivityPub and optional ATProto phases.
Re-invoking ATProto from the unified-account facade can create fresh signing
keys and duplicate or conflict with submitted PLC operations. The facade now
uses `signupProvisioning` evidence returned by `auth.signup`, performs a
read-only AP actor readiness check, and checks the protected identity binding
instead of repeating ATProto provisioning. A missing or inconsistent binding
fails closed. It does not return or persist the login JWT in the account API.

**Critical ATProto limitation:** `atproto-provisioning.initializeRepoState`
currently writes a placeholder root CID and revision into the RDF identity
binding; it does not create an actual signed repository commit/CAR on a
working PDS. This PR now rejects this path in production even if a legacy
binding already contains `repoInitialized=true`. Real PLC submission is a
separate step and is not evidence of an initialized PDS. Production
provisioning is explicitly blocked pending independently verified PDS
repository creation and consistency, not silently declared complete.
The production `auth.signup` endpoint now rejects before creating any account,
WebID, signing key or PLC genesis operation while that repository adapter is
missing. Existing account login is unchanged. This fail-fast gate must only
be replaced by reviewed and verified real PDS bootstrap integration; an
environment variable or boolean binding is not sufficient evidence.

**Unknown RPC outcomes:** the API sets an irreversible-work boundary before
invoking `unified-account.create`. If the call times out, throws after
partial work, or returns but the completion ledger cannot confirm storage,
it now returns `ACCOUNT_PROVISIONING_UNCERTAIN` or
`ACCOUNT_COMPLETION_UNCERTAIN` without declaring the claim failed or
allowing a new identity to be issued. Both paths have regression coverage.
This conservatively preserves the reservation until explicit reconciliation,
not indefinitely retried automatic signup.

**Critical durability limitation:** `provider-capabilities` idempotency and
`account-provisioning-state` phases currently use per-process Maps. Both
must reject production reservations/starts, because a second Moleculer cell
or restart can lose the only record of irreversible account creation. If an
account has already been created and storing its completion fails, the API
now returns `ACCOUNT_COMPLETION_UNCERTAIN`, does not report 201, and does
not release the reservation as safely retryable.

### PostgreSQL account control-plane candidate (not activated)

- `pod-provider/backend/sql/paper-account-postgres-lifecycle-candidate-v1.sql`
  defines a **separate account lifecycle** schema with unique
  provider-scoped username, provider/app/idempotency digest and optional
  keyed-email-HMAC constraints. It does not replace the live
  `@semapps/auth` accounts dataset or Group PostgreSQL control plane.
- `pod-provider/backend/candidates/account-postgres-lifecycle.js` is an
  explicitly injected, non-autoloaded pool adapter with transactional
  `reserve → account_created → identities_ready → completed` transitions.
  Unknown commits, stale leases and claims with an existing operation
  **require reconciliation**, never automatic second DID issuance.
- `paper-account-postgres-lifecycle.yml` runs a real disposable PostgreSQL
  18 schema proof: collisions must fail, and placeholder-PDS completion
  cannot pass the SQL constraints. This is not yet an end-to-end account
  authority or a production connection.
- No passwords, bearer tokens, recovery keys or raw email are kept in
  this lifecycle table. The `verified_email_hmac` is HMAC-SHA-256 with an
  external provider-held key, never unsalted SHA-256 of an email.

**Next required integration order:** a single authenticated provider
provisioning grant and durable PostgreSQL claim; reuse the existing
`auth.signup` authority while migrating only the operational lifecycle;
checkpoint each completed side effect with exact operation ID; explicitly
create and verify Pod/SAI/ACL resources; submit PLC once with reconciled
directory state; bootstrap a real signed PDS repo; seal the WebID=AP actor
and DID binding; atomically confirm completion. Test SIGKILL and unknown
COMMIT, conflicting same-name requests, expired leases, failed PLC/PDS,
actual Solid-OIDC consent revocation, database failover and PostgreSQL
backup/restore before activating a new account path.

PostgreSQL will own account/reservation transactions only **after** the
single-writer migration gate. Jena remains canonical for Pod RDF and
enforced Solid data rights. Separate read-only projections must not add a
second mutable authority. The planned Group PostgreSQL migration remains
a distinct consent-fenced cutover.

 
## Reliability and migration acceptance (still required)

- All phases (account reservation, Pod+WebID, AP, did:plc/PDS and
  identity-binding storage) need an **idempotent durable lifecycle**;
  crashing between phases must not cause a second DID, orphan a key or
  leave a reused username independently provisioned. Use the existing
  provisioning-state and identity binding services as the initial
  integration points.
- Test two concurrent signups for the same username and email,
  repeated operation UUID, SIGKILL before and after did:plc submission,
  PDS unavailable/slow, real PLC directory key and DID resolution,
  same public actor URI after restart, full SAI/WAC and Solid-OIDC
  readiness, durable restore and account deletion/export.
- The current 4-cell mixed-Redis setup still reports incomplete
  `pim:preferencesFile`, `interop:hasAuthorizationAgent` and
  `interop:hasRegistrySet` during bootstrap. Mandatory DID creation
  MUST NOT be used to hide that independent Solid lifecycle failure.
- Never put private signing keys or credentials in PostgreSQL shadow
  profiles. If PostgreSQL later becomes the canonical auth-account
  store, keep external WebID/AP/DID identifiers invariant through a
  single-writer migration as described in
  `docs/activitypods-postgres-account-and-groups-decision.md`.

The code in this PR establishes **synchronous success invariants** but
does not yet deliver the multi-node durable recovery/PLC-directory
acceptance above. Keep production release/rollout dependent on the
verified provisioning state machine, not only unit tests.

References: https://atproto.com/specs/did-plc
https://atproto.com/specs/atp
https://solid.github.io/solid-oidc/
