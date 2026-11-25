# Independently retained OAuth pre-denial intent — WORM candidate

**NONACTIVATED. Production signup/PDS OAuth issuer release CLOSED.** This
candidate is preparatory contract work, not a deployed revocation workflow.

## Implemented

A strict new versioned immutable receipt prefix is recognized by the
existing S3-compatible COMPLIANCE receipt grammar:

`paper/oauth-witness/pre-deny/v1/<subject-sha256>/<padded-oauth-epoch>/<operation-id>`

The authenticated owner, managed client, exact grant and revision are
inherited from the certified post-enrollment owner reader introduced in
ActivityPods #314. The subject hash reuses the existing witness domain.
The operation ID is deterministic for the exact owner/client/grant/epoch
to permit independent reconciliation of an ambiguous failed PUT without
creating unbounded new keys. Receipt bytes include the exact scope SHA256,
credential epoch and SAI revision; no password, token, access rights or
user-readable profile are written to storage.

The new `oauth-pre-deny-intent-coordinator.mjs` requests the existing
provider-neutral `oauth-portable-s3-receipt-writer.mjs` for write-once
storage, version enumeration, uncached independent GET, exact SHA256,
per-version COMPLIANCE retention and minimum remaining retention. It
cannot proceed to signer publication on any archive failure, ambiguous
ACK, unsafe version history, malformed response or mismatch.

After verified archive evidence, it asks a separately privileged,
monotonic **head publisher interface** to publish the exact retained
receipt. The new `oauth-pre-deny-signed-head.mjs` checks an independently
challenge-signed Ed25519 response, exact subject/grant/revision/receipt
correlation, canonical signed bytes, fresh nonce, trusted public-only key
and bounded skew. No old cached positive response or stale signer is
acceptable. The production signer, custody credentials and irreversible
high-water persistence are not implemented here; the injected signer
interface in CI is a test double.

Every component is gated by `NODE_ENV=test`, explicit disposable flags
and `fixtureOnly=true`. Production services do not import the code.
The coordinator returns a receipt with `releaseAccepted:false`, and
does **not** call an OAuth revoker, Redis, SAI/Jena or a PDS writer.
The existing portable S3 writer additionally reports that real hostile
conditional-create and operator-independent custody have not been verified.

## CI acceptance

The S3 archive workflow exercises the strict versioned PRE-DENY receipt
through the existing portable-S3 command transport test, checking real
`PutObject(IfNoneMatch='*')` request shape, version history, independent
GetObject/retention checks and incorrect conditional-PUT detection with
an isolated deterministic S3 mock. It also tests invalid owner/grant,
scope, credential epoch, lost PUT ACK, unsafe retention, bad digest,
lost signer ACK, wrong signature, private key rejection, unsigned
replay, wrong subject/revision, stale clock, and strict production
nonactivation. No cloud provider is contacted and no compliance claim
is inferred from the mock or its `releaseAccepted:false` result.

## Still production-critical

1. Independently administered signer and *nonrewindable latest head*,
   proven to survive signer/primary/witness/database restore and
   adversarial partitions; independent WORM-backed creation and
   archival of the PRE-DENY head.
2. Live S3-compatible Object Lock **COMPLIANCE** >=400 days with
   explicitly separated writer, readback, retention-admin and signing
   principals, verified conditional creation, denied overwrite/delete,
   no retention shortening, complete version enumeration and history
   after failed/ambiguous writes. AWS is not required, but provider
   compliance has to be measured rather than assumed.
3. Before any primary revoke/replace/uninstall mutation: serialize with
   all pending signed-PDS writer intents and their independently retained
   commit/abort receipts. No timeout-based abort can clear an ambiguous
   signed PDS commit.
4. Enforce latest independent pre-denial **BEFORE** every OAuth code,
   access JWT, encrypted refresh, DPoP, browser session and PDS writer
   admission. A receipt that is not consumed by every authorization
   path cannot prevent a restored grant from becoming active.
5. Only then implement restricted PostgreSQL owner/SAI/credential/grant
   CAS and durable blocked witness epoch, followed by Redis token-family
   tombstoning, recovery with independently audited physical
   PG/Redis/Jena/PDS backups, hosted positive signup, historical
   credential rotation and security/performance signoff.

**A passing test-only WORM receipt is not a revocation acknowledgment or a
production authorization fence.** Do not open the release fuse.
