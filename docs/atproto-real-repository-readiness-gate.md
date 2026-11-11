# Mandatory verified managed ATProto repository gate

**Status: DRAFT integration contract, NOT production activation.**
**Parent:** draft PR #134 mandates WebID = ActivityPub actor and managed did:plc.
**Proof:** draft PR #139 supplies a nonactivated real signed empty-repository/PG18 + native outbox acceptance. The actual trusted Moleculer adapter between the two PRs is **not yet implemented**.

## Problem prevented

The existing ActivityPods atproto-provisioning service's initializeRepoState() used to set repoInitialized:true with default root CID 'bafyreigenesisplaceholder' and revision '0', without generating an actual signed ATProto repository. Pure shape validation then allowed signup to report a complete dual-protocol account.

A real managed account must instead possess an actual signed v3 repo head, CID-addressed MST and verifiable CAR, with the account's current commit key bound to its publicly resolvable did:plc. This is distinct from simply having valid WebID/AP and PLC identity strings.

## Contract in this draft

- Production (NODE_ENV=production) always enters the signed-repository readiness branch; nonproduction can also opt in with APODS_ATPROTO_REQUIRE_VERIFIED_REPO=true.
- Calls **internal, trusted** 'atproto-managed-repository.bootstrapAndVerify' before writing the repo bootstrap metadata. It must derive the account DID and signer from protected provider-owned identitybindings and authorized session/grant context, and verify actual CAR/commit/MST and native outbox data. It may never accept an arbitrary user-provided actor or a success boolean as sufficient proof.
- Rejects absent/failed authority, mismatched account/DID, invalid version-1 DAG-CBOR SHA-256 CIDs, missing proper TID revision or missing outbox evidence. Returns an explicit 503, never an artificial repoInitialized:true.
- Writes only a sanitized root CID and TID rev to protected RDF identitybindings; never forwards private keys, CAR bytes or arbitrary service output.
- Re-reads the repository via internal 'atproto-managed-repository.verifyReady' after the binding write and requires exact root CID and revision agreement. This is a TOCTOU protection, not a replacement for durable version fencing.
- Preserves existing *nonproduction fixtures* to avoid rewriting unrelated legacy tests; the fixture path returns fixtureOnly:true. It is not valid proof for production readiness.
- Does **not** register or expose any new public XRPC/REST service and does not add a new identity authority. The contract actions do not yet exist; production account creation therefore **correctly fails closed** until the separately reviewed signed repository authority implementation is integrated.

## Dedicated executable tests

The no-dependency Node.js workflow runs production-path tests (without requiring the backend dependency graph or libvips) for:
- fake or partially specified evidence and invalid DID/root/rev;
- missing internal authority with **zero identitybinding writes**;
- successful verified structured evidence with sanitized persisted binding;
- post-write mismatch rejection on a synthetic/stale repo head;
- explicit nonproduction fixture classification.

The real independent CAR/signature/PG18 tests are in PR #139; the two PRs must be integrated and tested together before production deployment.

## Remaining release gates

- [ ] Add the authorized ActivityPods-owned 'atproto-managed-repository.bootstrapAndVerify' and '.verifyReady' Moleculer actions backed by real durable repo storage, cryptographically checked key/PLC identity and native-event outbox, not user-supplied metadata.
- [ ] Reconcile PG repo persistence with Jena identitybinding across crash/restart and concurrent account signup; settle on exactly one canonical managed repository writer and key-custody authority.
- [ ] Prove real device/user delegated auth, SAI revocation and no arbitrary actor signing/IDOR; private key custody stays in ActivityPods.
- [ ] Add signed initial commit and later record mutations, complete CAR export, monotonic TID rev and distributed CAS/locking with recovery.
- [ ] Verify live did:plc resolution and actual PDS XRPC and relay ingestion, native firehose publication and outage retry; independent reference suite and 4-replica failure injection.
- [ ] All exact-head backend and integration CI green, rollback plan, documented deployment and separate activation approval.

**Do not merge or deploy this contract independently of the real authority service.**
