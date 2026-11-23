# Paper S3 archive qualification: Backblaze B2, Storj and Filebase

**2026-11-23 — NONACTIVATED. Production signup and staging release CLOSED.**

## Protocol and custody comparison

| Provider | S3 API | Object Lock COMPLIANCE | Versioned retained objects | Result for Paper |
|---|---|---|---|---|
| AWS S3 | Yes | Yes | Yes | Existing STS/ExpectedBucketOwner custody proof, still awaits independent live certification |
| Backblaze B2 | Yes | Yes | Yes | Candidate; needs real create-only, delete-marker, IAM/custody and independent-head qualification |
| Storj | Yes | Yes | Yes | Candidate; needs live create-only, access-grant and independent-head qualification |
| Filebase | Yes (subset) | No equivalent documented | ListObjectVersions and PutBucketVersioning unsupported | Not suitable for immutable OAuth/credential latest-head authority; still suitable for ordinary media/IPFS |
| Cloudflare R2 | Yes (subset) | Removable bucket locks, not AWS COMPLIANCE | Different model | Disposable integration fixture, not independent nonrewindable authority |

Primary source documentation:
- https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api
- https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
- https://www.backblaze.com/apidocs/s3-put-object
- https://storj.dev/dcs/buckets/object-lock
- https://storj.dev/dcs/api/s3/credentials
- https://storj.dev/dcs/api/s3/s3-compatibility
- https://filebase.com/docs/recipes/migrate-from-aws-s3
- https://filebase.com/docs/s3-api/compatibility-matrix
- https://developers.cloudflare.com/r2/buckets/bucket-locks/

## Three independent gates, not one

**S3 behavior:** COMPLIANCE retention alone does not prove atomic
create-only PutObject with If-None-Match:*, exact immutable version
lookup, delete-marker visibility or correct lost-ACK handling.
Backblaze's published PutObject header list does not document the
conditional create-only header. Storj's basic S3 support does not
imply every AWS optional conditional behavior. A real provider-specific
race and retention test is required; no silent fallback or unsafe retry.

**Account separation:** the archive must belong to a genuinely
different human-operated organization/project or account, with
independent administration, credentials, recovery and controlled
account deletion. Two S3Client objects or credentials within the same
provider project do not establish independence. Backblaze app keys use
B2 capabilities; Storj uses access grants/macaroons rather than AWS
IAM and STS numeric account IDs. The AWS-only verification remains
untouched and must not be weakened with fake STS results.

**Monotonic latest-head:** a protected *historical* receipt does not
prove it is the latest credential epoch after a PostgreSQL rollback.
An independently administered service must durably track and
freshly sign the true latest monotonic credential head, retaining
receipts with proper COMPLIANCE retention and demonstrating recovery.

## Read-only qualifier implementation

Source: pod-provider/backend/candidates/oauth-portable-s3-custody-readonly.mjs
Test: pod-provider/backend/scripts/proof-oauth-portable-s3-custody.mjs
Operator: pod-provider/backend/scripts/probe-oauth-portable-s3-custody.mjs

Only official HTTPS origins are allowed:
- Backblaze B2: https://s3.<region>.backblazeb2.com/
- Storj: https://gateway.storjshare.io/

The qualifier uses six real S3 command types: GetBucketVersioning,
GetObjectLockConfiguration, ListObjectVersions, HeadObject,
GetObjectRetention, GetObject. It checks versioning enabled,
COMPLIANCE default retention of >=400 days and >=30 days remaining
for an exact historical object sample. The sample's immutable
version ID, canonical receipt fields and SHA256 must match.
Unexpected version history, changed latest version or a delete
marker fails closed. Responses are length-bounded, TLS verification
is mandatory, and automatic SDK retry is disallowed.

All observations ALWAYS set releaseAccepted=false,
operatorIndependenceVerified=false, latestHeadVerified=false and
conditionalCreateOnlyVerified=false. Even a correct retained
historical receipt cannot authorize a newly signed login or signup.

## Connecting B2 or Storj to the deployed Paper backend

1. An independent operator provisions a private Object Lock bucket,
   turns on COMPLIANCE default retention, and creates an explicitly
   scoped read-only application key/access grant. Test retention
   duration in a disposable bucket first. Do not provide keys in chat.
2. On that operator's trusted machine, install the pinned AWS
   SDK v3 packages outside the source checkout:
   @aws-sdk/client-s3@3.1174.0 and
   @aws-sdk/credential-providers@3.1174.0.
   Store the read-only credentials in a local AWS shared-profile file
   with restrictive OS permissions.
3. Set PAPER_PORTABLE_WORM_OPERATOR_CONFIRM=read-only-verified,
   PAPER_WORM_SDK_ROOT, PAPER_PORTABLE_WORM_READER_PROFILE,
   PAPER_PORTABLE_WORM_PROVIDER (backblaze-b2 or storj),
   PAPER_PORTABLE_WORM_ENDPOINT, PAPER_PORTABLE_WORM_BUCKET and
   PAPER_PORTABLE_WORM_PHASE=preflight. Run the operator script
   with Node 22+. It performs only configuration reads.
4. To read an independently recorded historical receipt set
   PAPER_PORTABLE_WORM_PHASE=receipt together with
   PAPER_PORTABLE_WORM_RECEIPT_KEY,
   PAPER_PORTABLE_WORM_RECEIPT_VERSION and
   PAPER_PORTABLE_WORM_RECEIPT_SHA256. The result still
   cannot authorize production release.

No B2 or Storj credential or account is directly connected to
this ChatGPT session. Connecting a ChatGPT app/plugin would need
an available vendor connector or explicit custom MCP gateway
installation. Alternatively, separately governed credentials can
be added to Paper's actual deployment secret store through a
reviewed runtime integration. The Cloudflare connection currently
administers Cloudflare only and cannot directly access B2/Storj.

## Remaining production requirements

A verified provider-specific write-once test, independent
operator/key custody, genuinely nonrewindable live latest-head
signer, authenticated SemApps/Solid/SAI/OAuth/PDS account-change
coordination, full PG/Jena/Redis/PDS recovery, hosted positive
unified signup and independent human review.

Do not enable production signup based on this read-only qualification.
