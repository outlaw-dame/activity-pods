# Unified-account positive acceptance — disposable milestone and hosted release gate

Checkpoint: November 21, 2026. Primary issue:
https://github.com/outlaw-dame/mastopod-federation-architecture/issues/186

## Current verified model

Paper owns the canonical new-account identity in ActivityPods. An owner
signs in and consents to the exact scoped Solid native SAI rights. The
same PostgreSQL account journal binds WebID, ActivityPub actor ID,
managed did:plc, handle, intended PDS URL, signed repo initialization
and permission request HMAC. The native SAI app registration and
grants must be independently read back from protected Jena before the
PG consent becomes current. No shadow group pod or extra user identity.

The test in
`pod-provider/backend/candidates/atproto-signed-repo-proof/pg-journal-bound-sai-live.mjs`
now continues **the same newly journal-bound synthetic account** into a
cryptographically signed secp256k1 ATProto genesis and
`app.bsky.feed.post` record. It reads the canonical WebID,
ActivityPub actor URI, handle, DID and PDS mapping, uses the
authenticated owner enrollment token to approve an exact PG OAuth
epoch, requires current PG OAuth and native SAI consent, persists
immutable DAG-CBOR/CID blocks, signed repository head and the native
outbox atomically, then independently verifies the signed CAR.
A malicious cross-account write and owner revocation are rejected,
and the immutable signed repository remains unchanged.

This is a **positive disposable database and cryptographic integration
fixture**, NOT a real public signup, hosted ATProto PDS, network
federation acceptance or production release. The account and
reservation records are created by the fixture's SQL seeder, not by a
real browser/HTTPS signup flow. The genesis projection is marked
applied by a clearly labelled disposable PG-only stand-in; a real
hosted flow must wait for actual protected-Jena readback and durable
delivery. The reference-MST signed writer's same-transaction native
SAI and PG OAuth row locks are tested separately under independent
SQL writer/revoker logins.

## Genuine hosted positive production acceptance requirements

A real, separately deployed staging provider must create a new
account from an authenticated browser request and its existing
PostgreSQL signup/reservation journal. The following must each be
proved from independent observers before opening the signup fuse.

1. One new unique account and durable operation/handle reservation.
   Verify immutable account ID, WebID, ActivityPub actor ID, managed
   DID and exact PDS service endpoint with HTTPS, validated DID PLC
   operation and hosted signing-key custody and rotation.
2. Solid provider and Pod creation via the real web/browser OIDC
   session. Real native SAI owner selection must match advertised
   required rights and optional rights, and the protected Jena
   credential must independently read back the same registration
   and grant. The normal browser/provider cannot impersonate the
   protected attestor.
3. Initial OAuth issuance must be derived from the owner-authenticated
   journal. Post-enrollment OAuth approvals/revocations require their
   own current owner-session guard, not reusing an expired signup
   enrollment token. Signed access JWTs and encrypted refresh
   sessions must carry and recheck exact PG consent epoch and the
   external non-rewindable witness. Prove DPoP nonce, method, htu,
   ath, cnf.jkt, replay denial and key rotation against actual XRPC.
4. The actual hosted signing worker must lock the exact PG OAuth
   generation and native SAI consent in its one signed repository
   commit transaction with immutable MST blocks, repo head, outbox
   and projection CAS. A separate independent reader validates
   DID signing keys, CAR block content/CIDs, MST root, TID revision
   and the returned `at://did:plc/.../app.bsky.feed.post/...` URI.
5. An independent remote AppView/PDS/relay and a genuine ActivityPub
   peer must fetch the new actor, WebID, DID and signed post,
   and verify successful inbox/outbox delivery, not just a queued
   local outbox row. Cross-platform interoperability does not
   require Mastodon relays; use ordinary actor semantics.
6. Revoke owner consent, rotate access/refresh family, kill provider
   or PostgreSQL process mid-commit, restore Redis snapshot, restore
   canonical PostgreSQL PITR and Jena, and fail over the witness.
   Old signed, unexpired credentials, browser cookies and
   revoked PDS writes must remain denied after every phase.
   Require a real independently immutable WORM witness receipt
   readback with separately authorized locking policies; a
   second database without such evidence is not sufficient.
7. Recheck provider TLS, least-privilege PG logins, protected
   Jena physical isolation, bounded retries/compensation,
   no duplicate accounts/outbox emissions, stable signing keys
   and no irreversible side effects on ambiguous ACK.
   Only after all 1–7 and CI security reviews pass may an explicit
   release PR propose changing `release=CLOSED`. Migration of
   existing ActivityPods/ATProto users remains a separate project.

The actual production/source staging still returns 503 for both
signup entrypoints by design. A test-only positive fixture does not
modify that fuse or provision production secrets, SQL roles or
a hosted PDS.

Official specification references:
https://atproto.com/specs/oauth
https://atproto.com/specs/repository
https://atproto.com/specs/sync
https://atproto.com/specs/did
https://atproto.com/guides/account-recovery
https://github.com/bluesky-social/atproto/tree/main/packages/pds
