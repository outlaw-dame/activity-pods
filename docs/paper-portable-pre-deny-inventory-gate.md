# Independent pre-denial archive inventory: read-only fail-closed candidate

**Status: NONACTIVATED, production signup and PDS OAuth CLOSED.**

## Problem addressed

A restored canonical PostgreSQL 18 database **and** a restored witness
PostgreSQL 18 database may both report an earlier, active owner grant.
Their agreement does not prove that an independently retained PRE-DENY
receipt was not committed after the snapshots. The existing signed
current-head admission prototype takes a private `readLatestArchive`
callback, not a concrete provider-neutral S3 pre-denial inventory.

## Increment implemented

`pod-provider/backend/candidates/oauth-portable-pre-deny-inventory.mjs`
is a strictly **read-only**, test-gated S3-compatible inventory that:

1. Takes only an independently authenticated, normalized 64-character
   **signed-write v5 length-framed** subject digest, never a browser-
   selected WebID, grant or client. It is NOT the legacy epoch-v1
   NUL-framed digest. The caller must certify native owner/SAI first.
2. Uses an injected, separately credentialed S3 reader and pinned
   Backblaze B2 / Storj / explicitly approved custom-S3 HTTPS endpoint
   to verify bucket versioning and default Object Lock COMPLIANCE >=400
   days, through the already-existing portable custody verifier.
3. Lists `ListObjectVersions` for the **exact subject's pre-deny/v1
   prefix**. It refuses pagination/truncation, delete markers,
   unexpected keys, unqualified versions, duplicates, and more than
   **one** retained PRE-DENY operation. One-way v7 does not yet support
   new-generation reapproval; multiple operations cannot be accepted
   until that protocol and high-water mapping have been reviewed.
4. Reads the exact S3 object version, enforces <=1024 bytes and the
   existing canonical pre-deny/v1 receipt schema, and computes SHA256.
   It then invokes the reused portable Object Lock exact-version
   verifier to independently recheck version history, HEAD,
   GET version/bytes/hash, COMPLIANCE remaining retention and bucket
   policy. It lists the subject again and rejects any observed change.
5. Returns `retainedDenialObserved:true` for a retained denial, useful
   to **veto** a restored old active grant. A clean/empty list returns
   `absenceAuthorizes:false` — not an ACTIVE claim. Every result
   reports `operatorIndependenceVerified:false`,
   `monotonicLatestHeadVerified:false` and `releaseAccepted:false`.

The test-only flag is `PAPER_OAUTH_PRE_DENY_INVENTORY_DISPOSABLE=confirmed`
with `NODE_ENV=test` and `fixtureOnly:true`. There is no production
service import, no token issue/revocation, no grant write, no unsigned
private signer, no object PUT, DELETE or policy mutation, no retry after
unknown state changes.

The independent S3 CI workflow exercises normal retained-denial and
empty-inventory results as well as malicious or incomplete history,
delete markers, duplicate versions, unexpected keys, stale readback,
lost GetObject/ListObjectVersions, corrupted bytes, invalid retention,
unqualified bucket, changed listing during read and production-mode
refusal. Tests execute against both command-shaped test doubles and
the exact pinned upstream AWS SDK's command classes; no live storage
credentials or provider certification are involved.

## Why this is not production authority

**This improves detection, not completeness of authorization.**
A provider could return stale or selectively incomplete version
history; two consecutive scans are not an atomic cut with a
concurrent PREPARE/PUT. An S3 COMPLIANCE receipt is not a
nonrewindable latest-head signer. An empty list cannot authorize a
new or restored JWT, refresh, DPoP, browser grant or signed PDS commit.
A prepared denial exists in independent PG **before** any WORM PUT
and must also veto use. The independent signer must preserve a
separately administered monotonic subject mapping across legacy
epoch-v1 and signed-intent-v5/PRE-DENY domains and reject its own PITR.
The PDS writer must durably reserve and reconcile each signed intent
before allowing a revoker to acknowledge a blocked operation.

## Remaining release gates

- Separately operated external COMPLIANCE Object Lock custody and
  a genuine nonrewindable latest-head signer; signed complete
  high-water inventory, independently verified credential/role/key
  custody, negative DELETE/overwrite/retention/race and operator PITR
  tests against the real chosen S3-compatible provider.
- Verified post-archive PRE-DENY publication and active writer fence
  integrated with actual ActivityPods Solid-OIDC/SAI owner proof,
  canonical PG, witness PG, Redis OAuth code/refresh, all DPoP/PDS
  endpoints and signed CAR/outbox transactions.
- Crash/partition/lost-ACK and physical PostgreSQL/Redis/Jena/PDS
  recovery, independent external security signoff, credential rotation,
  hosted positive signup and performance acceptance.

Sources: [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[AWS Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html),
[Backblaze B2 Object Lock](https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api),
[Storj Object Lock](https://storj.dev/dcs/buckets/object-lock),
[Cloudflare R2 bucket-lock differences](https://developers.cloudflare.com/r2/buckets/bucket-locks/).

**No production grant or signup fuse may be opened as a result of this test.**
