# Paper R2 disposable witness integration (provider-neutral transport)

**Status: NONACTIVATED; production signup is CLOSED.** An S3-compatible
transport is not synonymous with AWS S3 Object Lock COMPLIANCE or an
independently administered archive. No production service imports the
candidate adapter.

## Actual Cloudflare staging inventory (read only after provisioning)

On 2026-11-22 the connected Cloudflare account had three unrelated R2
buckets: `atlas-discovery-staging-backups` (Atlas-specific 30-day
retention on `gateway-staging/`), `damonoutlaw`, and `nosflare`.
**None may be repurposed for Paper.**

A fourth bucket **`paper-witness-disposable-tests`** was created in the
North America East location, Standard storage class, non-public by
default. The management API PUT/GET round-trip verified an enabled
30-day age-based lock for only `paper/oauth-witness/`. Do not
accidentally test deletion against unrelated buckets. The lock can be
removed by authorized Cloudflare administrators.

This provisioned bucket is a **disposable integration fixture**, not a
trusted production authority. The connector currently provides
management API access; no S3 access-key credential was retrieved and no
real S3 conditional PUT or object readback has yet been performed.
No canonical epoch or signed-intent receipt was written to this bucket.

### Real Cloudflare management API smoke test (2026-11-22)

A strictly disposable object was created at
`paper/oauth-witness/fixtures/r2-management-readback-v1` using the
account-scoped R2 **management API**, with 51 bytes of public nonsecret
fixture content. GET returned the exact original 51 bytes. A second PUT
to the same key with different test bytes failed with HTTP **409**;
subsequent GET confirmed the original bytes were unchanged and the
30-day prefix lock remained enabled. This directly verifies that the
current R2 lock protects this test object from ordinary overwrite, but
**does not test S3-HMAC If-None-Match, object version history, operator
separation, delete-rule privilege, or post-PITR revocation safety.**
This fixture is retained for 30 days under the configured bucket rule.


## Why the adapter differs from AWS S3

R2 supports S3-compatible `PutObject`, `If-None-Match: *` create-only
semantics, `HeadObject`, `GetObject` and `ListObjectsV2`.
R2 bucket locks use **Cloudflare account-scoped management API**:
`GET /accounts/{account_id}/r2/buckets/{bucket_name}/lock`, returning
`rules` with `prefix`, `enabled` and `condition`. Unlike AWS
Object Lock COMPLIANCE, R2 lock rules can be removed by an account
administrator. AWS versioned COMPLIANCE commands, bucket-owner numeric
ID checks, STS role inspection and GetObjectRetention are NOT R2
configuration probes. Never weaken AWS compliance checks to make R2 pass.

Primary documentation:
- https://developers.cloudflare.com/r2/api/s3/api/
- https://developers.cloudflare.com/r2/api/s3/conditional-operations/
- https://developers.cloudflare.com/r2/buckets/bucket-locks/
- https://developers.cloudflare.com/r2/get-started/s3/

## Candidate API and security contract

`pod-provider/backend/candidates/oauth-r2-receipt-archive.mjs` offers
`putAndVerify` and `readLatestEpoch`, deliberately sharing the one
canonical receipt validator used by the AWS COMPLIANCE adapter.

- Requires a distinct writer and reader transport, checked account ID
  and bucket, a read-only `getLockRules` that queries Cloudflare R2
  management API, and scoped minimum-retention lock on the entire witness
  prefix.
- Performs conditional create-only PUT and exact bytes readback.
  An ambiguous PUT response is not retried unconditionally.
- On recovery, requires a separately supplied independently retained
  `{subject, revision, sha256}` high-water checkpoint; checks contiguous
  ordered epoch keys and compares canonical latest bytes and digest.
- Refuses missing/changed policy, missing receipts, truncated/cyclic
  pages, gaps, forged checkpoints, oversized payloads and wrong scope.
- Always returns `independentlyImmutable:false` and
  `releaseAccepted:false`. Constructor is locked behind
  `NODE_ENV=test`, explicit fixture-only flag and
  `PAPER_OAUTH_R2_DISPOSABLE=confirmed`.

**Security boundary:** The adapter's injected checkpoint is not itself
proof that the checkpoint is independently retained or authenticated.
A production witness must validate out-of-band signatures and fresh,
non-rollbackable checkpoint custody, then reconcile commit ACK, PDS
signing and all credential/consent revocations. An R2 bucket under the
same operator remains outside that independent trust boundary.

**Operational constraint:** The fixture lists up to 4096 epochs (8
pages) to prove gap/fork detection. This is O(history) and must not be
shipped on the hot authorization path. Before promotion implement and
test externally certified monotonic high-water and bounded consistency
proofs with audited cost and crash-recovery semantics.

## Next acceptance tests

1. Provision **separate, narrowly scoped R2 S3 test-only access
   credentials** outside GitHub/source. The Cloudflare connector's
   management authorization is not a substitute for S3 HMAC keys.
2. Execute actual `If-None-Match: *` PUT, duplicate 412, ambiguous ACK,
   ContentLength/bytes, list pagination, and lock-policy mutation tests
   in this isolated disposable bucket. Never log credentials or
   owner-identifying payloads.
3. Implement independent signed monotonic checkpoint custody, not a
   second database snapshot under the same restore authority.
4. Prove latest revocation after independent physical PITR of both
   PG18 clusters, Redis/Jena and PDS; test credential rotations in all
   SemApps/SAI/ATProto paths.
5. Keep federation staging `release=CLOSED` until full hosted positive
   new-account E2E and independent security review.
