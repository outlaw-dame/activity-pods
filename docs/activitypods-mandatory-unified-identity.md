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
