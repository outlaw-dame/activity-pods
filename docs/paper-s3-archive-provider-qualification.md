# ActivityPods / federation-sidecar S3 archive capability qualification

**2026-11-23 — NONACTIVATED. Unified-account signup and staging release CLOSED.**

Paper and Memory are application branding options. This is a canonical
ActivityPods identity/authorization and sidecar integration gate; the
storage contract must never depend on either product name or an AWS
account ID. `paper/*` paths and prefixes below are existing source
identifiers for fixtures and migration compatibility, not a mandate
that the final application be named Paper.

## Protocol and custody comparison

| Provider | S3 API | Object Lock COMPLIANCE | Versioned retained objects | Result for Paper |
|---|---|---|---|---|
| AWS S3 | Yes | Yes | Yes | Existing STS/ExpectedBucketOwner custody proof, still awaits independent live certification |
| Backblaze B2 | Yes | Yes | Yes | Candidate; needs real create-only, delete-marker, IAM/custody and independent-head qualification |
| Storj | Yes | Yes | Yes | Candidate; needs live create-only, access-grant and independent-head qualification |
| Filebase | Yes (subset) | No equivalent documented | ListObjectVersions and PutBucketVersioning unsupported | Not suitable for immutable OAuth/credential latest-head authority; still suitable for ordinary media/IPFS |
| Cloudflare R2 | Yes (subset) | Removable bucket locks, not AWS COMPLIANCE | Different model | Disposable integration fixture, not independent nonrewindable authority |
| Other S3-compatible provider | Depends on verified implementation | Must actually enforce COMPLIANCE or a proven equivalent | Must verify immutable exact versions and history | Operator-pinned custom S3 endpoint may be inspected, but no acceptance without independently observed capabilities |

Primary source documentation:
- https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api
- https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
- https://www.backblaze.com/docs/cloud-storage-iam-sts-api
- https://www.backblaze.com/apidocs/getcalleridentity-get
- https://www.backblaze.com/docs/oidc-workload-identity-with-backblaze-iam
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
provider project do not establish independence. Most Backblaze accounts use restricted B2 application keys.
Backblaze also introduced AWS-compatible IAM/STS in 2026, including
GetCallerIdentity, AssumeRole and OIDC workload identity; this is
limited to eligible Enterprise Web Console customers and uses
https://sts.backblazeb2.com (NOT AWS regional STS). A separately
governed B2 account with confirmed enterprise IAM entitlement can
undergo an additional Backblaze-specific STS identity audit.
Never silently treat that as AWS STS, and never require it on a
standard B2 app-key account that cannot use it. Storj uses access
grants/macaroons rather than AWS IAM and STS numeric account IDs.
The AWS-only verification remains untouched and must not be
weakened with fake STS results.

**Monotonic latest-head:** a protected *historical* receipt does not
prove it is the latest credential epoch after a PostgreSQL rollback.
An independently administered service must durably track and
freshly sign the true latest monotonic credential head, retaining
receipts with proper COMPLIANCE retention and demonstrating recovery.

## Read-only qualifier implementation

Source: pod-provider/backend/candidates/oauth-portable-s3-custody-readonly.mjs
Test: pod-provider/backend/scripts/proof-oauth-portable-s3-custody.mjs
Operator: pod-provider/backend/scripts/probe-oauth-portable-s3-custody.mjs

Known providers use fixed official HTTPS origins:
- Backblaze B2: https://s3.<region>.backblazeb2.com/
- Storj: https://gateway.storjshare.io/

**Any other S3-compatible implementation** may use the additional
read-only `custom-s3` mode when an independent operator explicitly pins
its **exact canonical HTTPS origin**. IP literals, local/internal/special
test DNS suffixes, credentials, query parameters, paths, unexpected
ports and mismatched operator pins are refused. The operator must still
perform independent DNS/TLS, role, retention, write-once and recovery
assessment; the pin alone is not a signed security approval.
Generic S3 mode accepts a reviewed region and path/virtual-host
addressing preference. Vendor-specific identity checks belong in a
separate provider capability module rather than faking AWS STS
and `ExpectedBucketOwner` on non-AWS services.

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

## Connecting a qualifying S3 provider to the ActivityPods backend

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
   PAPER_PORTABLE_WORM_PROVIDER (`backblaze-b2`, `storj` or `custom-s3`),
   PAPER_PORTABLE_WORM_ENDPOINT, PAPER_PORTABLE_WORM_BUCKET and
   PAPER_PORTABLE_WORM_PHASE=preflight. For `custom-s3`, the operator
   **must also set** PAPER_PORTABLE_WORM_APPROVED_ENDPOINT equal to
   the canonical independently reviewed origin, and explicitly set
   PAPER_PORTABLE_WORM_REGION. The optional
   PAPER_PORTABLE_WORM_URL_STYLE is `path` (default) or
   `virtual-host`. Run the operator script
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

## Open-source and self-hosted S3 considerations (current sources)

Avoid equating a project's S3 logo or API list with reliable WORM
behavior. Open-source Garage does not yet support Object Lock or object
versioning (https://github.com/deuxfleurs-org/garage/blob/main-v2/doc/book/reference-manual/s3-compatibility.md).
SeaweedFS documents Object Lock and conditional PutObject, **but**
upstream issues have reported COMPLIANCE-retention DELETE enforcement
defects (https://github.com/seaweedfs/seaweedfs/issues/8350 and
https://github.com/seaweedfs/seaweedfs/issues/11333). It is NOT
qualified for this high-trust archive until the installed exact
version passes independent hostile DELETE/retention tests.
MinIO AIStor documents COMPLIANCE and conditional PutObject
(https://docs.min.io/aistor/developers/s3-api-compatibility/ and
https://docs.min.io/aistor/administration/object-locking-and-immutability/),
but the original AGPL MinIO community edition is no longer maintained;
the supported AIStor offering is commercial
(https://www.min.io/pricing). This should be accounted for when
weighing open-source maintenance and operating cost.

The `custom-s3` mode is intentionally a **read-only capability probe**
rather than a product certification. Real negative immutability and
conditional-write races remain mandatory for *every* actual provider,
and production keys/last-signed-head custody must be external to
ActivityPods and the federation sidecar.

## Provider-neutral create-only WORM receipt transport (NONACTIVATED)

The identity authority and federation sidecar must not require an
AWS-specific numeric account ID or AWS STS protocol for S3 *data*
operations. The new candidate in
`pod-provider/backend/candidates/oauth-portable-s3-receipt-writer.mjs`
provides an S3-only conditional write with provider-neutral verified
readback, using the same operator-pinned HTTPS origins and canonical
receipt validator as the read-only qualifier.

The transport has three deliberately separated guarantees:

1. It requires distinct writer/reader SDK clients, **both with SDK
   `maxAttempts=1`**, and observed bucket versioning plus default
   COMPLIANCE retention before even attempting a PUT. No response,
   credential or origin can override this gate. The caller supplies
   only one exact canonical receipt key and bytes; the transport sets
   `IfNoneMatch:'*'`, with no public ACL, TTL shortcut, or provider-
   specific IAM parameters.
2. After a PUT (including a timeout, HTTP 412 or lost acknowledgment),
   it **never retries the mutation**. It asks the separate read
   transport for all versions at that exact key, requiring exactly
   one latest version and zero delete markers. It rejects extra
   versions (a provider that ignored the precondition), changed
   version IDs, conflicting bytes, unexpected object lengths or an
   overwritten current object.
3. It uses the already-existing provider-neutral six-command S3
   verifier to recheck bucket COMPLIANCE, object-version retention,
   the exact receipt bytes and SHA-256, and the current version after
   readback. Returned evidence is permanently labelled
   `conditionalCreateOnlyVerified:false`,
   `operatorIndependenceVerified:false`,
   `latestHeadVerified:false`,
   `releaseAccepted:false`.

The disposable regression covers first PUT, same-key exact retry
reconciliation, conflicting old bytes, lost ACK before/after durable
commit, ignored `IfNoneMatch` creating extra versions, unsafe bucket
GOVERNANCE/disabled versioning, delete markers, corrupted bytes,
stale PUT acknowledgment version, automatic SDK retry counts, missing
operator endpoint pin and attempted production activation.

**This is not a live vendor certification.** The regression uses a
synthetic, version-aware S3 protocol fixture; real Backblaze, Storj,
Ceph, MinIO AIStor or any other operator-pinned gateway MUST undergo
a separate authorized disposable-bucket conditional-create race and
WORM retention test. The transport is not imported by the live
ActivityPods account or federation services. A separate protected
signer must still establish monotonic latest authorization state, and
a separately administered WORM account must preserve proof after
PostgreSQL, Redis, Jena and PDS restore.

Do not confuse a passing `PutObject` readback with proving the
provider would reject an attempted overwritten object. That
requires the explicit negative live race test and IAM/retention
independence evidence. Remain `release=CLOSED`.

## Disposable S3 conditional-create acceptance (two actual concurrent writes)

A *read-only* COMPLIANCE/versioning checklist cannot prove the critical
`If-None-Match: *` create-only behavior used by the ActivityPods
authorization receipt archive. A separate strictly operator-invoked
acceptance tool now lives at:

- `pod-provider/backend/candidates/oauth-portable-s3-writeonce-probe.mjs`
- `pod-provider/backend/scripts/probe-oauth-portable-s3-writeonce.mjs`
- `pod-provider/backend/scripts/proof-oauth-portable-s3-writeonce.mjs`

**This is an irreversible-storage test**: ONE synthetic object version
may be retained under COMPLIANCE for at least 400 days. Use a new,
empty, individually approved bucket named
`paper-worm-disposable-<random-suffix>`. Its object key is derived
from a cryptographically random subject and uses the existing
`paper/oauth-witness/epochs/v1/<hash>/<revision>` test namespace.
It contains **no real WebID, credentials, signing keys, consent or user
data**. The tool intentionally provides no cleanup/delete operation.
Factor the tiny but nonzero lock/storage cost and the bucket's
retention policy into operator approval.

Required environment, IN ADDITION TO the read-only probe SDK/endpoint
settings, with a separately provisioned **disposable writer** profile:

- `PAPER_PORTABLE_WORM_OPERATOR_CONFIRM=disposable-write-approved`
- `PAPER_PORTABLE_WORM_WRITE_DISPOSABLE=confirmed`
- `PAPER_PORTABLE_WORM_BUCKET=paper-worm-disposable-<random-suffix>`
- `PAPER_PORTABLE_WORM_WRITE_ACK=permanently-retain:<exact-bucket-name>`
- `PAPER_PORTABLE_WORM_WRITER_PROFILE=<disposable-writer-profile>`
- `PAPER_PORTABLE_WORM_READER_PROFILE=<distinct-read-only-profile>`
- `PAPER_PORTABLE_WORM_PROVIDER=backblaze-b2|storj|custom-s3`
- `PAPER_PORTABLE_WORM_ENDPOINT=<exact-vetted-HTTPS-origin>`
- `PAPER_WORM_SDK_ROOT=<absolute-path-to-pinned-SDK-install>`

For `custom-s3`, also pin the *same exact* origin with
`PAPER_PORTABLE_WORM_APPROVED_ENDPOINT` and provide
`PAPER_PORTABLE_WORM_REGION`. Optional
`PAPER_PORTABLE_WORM_URL_STYLE=path|virtual-host`.

Run only on the independent operator's trusted host, with protected
local S3 profiles and the pinned SDK versions documented above:

```sh
node pod-provider/backend/scripts/probe-oauth-portable-s3-writeonce.mjs
```

The probe first verifies versioning and COMPLIANCE default retention
through a **separate reader client**. It then sends exactly two
competing `PutObject` requests with **different canonical synthetic
receipt bodies** to the same new key, with `IfNoneMatch: '*'`,
content MD5 and SHA-256. Neither PUT is retried, even after lost ACK
or an ambiguous error. Acceptance requires *exactly one* successful
HTTP 200/201 ACK with a nonempty version ID and *exactly one* recognized
HTTP 412 PreconditionFailed or 409 ConditionalRequestConflict. Both
succeed, both conflict, or uncertain/timeout outcomes all fail. This
proves a real single-winner conditional-create observation only; the
provider can still have other concurrency defects outside this run.

After the race, the reader independently verifies that the exact
version is current, the version listing has no competing versions or
delete markers, the retained bytes match the winning SHA-256, the
object has COMPLIANCE retention with >=30 days remaining, and bucket
policy still has >=400 days configured. Failure is **not** automatically
retried. The synthetic key, version and digest may be kept for
an independent auditor to perform separate hostile DELETE, retention
shortening, delete-marker/overwrite and account-closure tests.

Outputs explicitly distinguish:
- `observedConditionalConflict: true` and
  `confirmedObjectRetention: true` for the **specific disposable
  sample only**;
- `independentlyAdministered: false`,
  `hostileDeleteRetentionVerified: false`,
  `monotonicLatestHeadVerified: false` and
  `releaseAccepted: false`.

A standard COMPLIANCE lock can prevent deleting/shortening an
**existing object version** without preventing a new version or
delete marker from being created. The real independent attestor must
therefore audit complete version history and maintain an externally
verified nonrewindable latest-head. Distinct writer/reader profile
names do NOT establish distinct human administration.

This code is **not loaded by the production Moleculer runtime**.
CI proves denial, SDK command contracts and no ambiguous write retry
only with disposable deterministic mocks; **CI does not claim a real
Backblaze/Storj/custom S3 provider passed the live write probe**.
The external signer, complete Redis/Jena/PDS restore, authenticated
owner account lifecycle, positive hosted signup and independent
human security review are still required. Production signup and
release remain CLOSED.

## Live exact-version COMPLIANCE hostility qualification (separately approved)

The existing two-writer conditional-`PutObject` probe establishes only
**one observed conditional race**. It cannot prove retention denies
attempts by an independent principal to delete a protected version or
shorten its retention. The additional operator-only tools are:

- `pod-provider/backend/candidates/oauth-portable-s3-hostile-lock-probe.mjs`
- `pod-provider/backend/scripts/probe-oauth-portable-s3-hostile-lock.mjs`
- `pod-provider/backend/scripts/proof-oauth-portable-s3-hostile-lock.mjs`

**Never run these against a production bucket or real user authorization
data.** The only accepted bucket format is
`paper-worm-disposable-<approved-random-id>`. The receipt must use the
exact v1 synthetic `paper/oauth-witness/epochs/v1/<64-hex>/0000000000000000001`
key and `VersionId` / SHA-256 from a prior successful **live**
`probe-oauth-portable-s3-writeonce.mjs` invocation. Use the
independent operator's own trusted host with pinned HTTPS provider
endpoint and **exact-version reader** and **adversary** S3 profiles
from separate credentials. Do not use a Paper, Railway, federation,
Cloudflare R2 or application deployment administrator as the
independent custody operator.

### Phase 1 — read-only approval challenge

Install precisely pinned Apache-2.0 SDK packages as documented above
in an isolated operator directory (outside source control). Configure
these nonsecret environment variables locally:

```sh
export PAPER_WORM_SDK_ROOT=/absolute/path/to/pinned-s3-sdk
export PAPER_PORTABLE_WORM_PROVIDER=backblaze-b2
export PAPER_PORTABLE_WORM_ENDPOINT=https://s3.us-west-002.backblazeb2.com/
export PAPER_PORTABLE_WORM_URL_STYLE=path
export PAPER_PORTABLE_WORM_BUCKET=paper-worm-disposable-approvedrandomid
export PAPER_PORTABLE_WORM_READER_PROFILE=separate-custody-reader
export PAPER_PORTABLE_WORM_RECEIPT_KEY=paper/oauth-witness/epochs/v1/YOUR_64_HEX_SUBJECT/0000000000000000001
export PAPER_PORTABLE_WORM_RECEIPT_VERSION=EXACT_VERSION_FROM_WRITEONCE_PROBE
export PAPER_PORTABLE_WORM_RECEIPT_SHA256=EXACT_SHA256_FROM_WRITEONCE_PROBE
export PAPER_PORTABLE_WORM_OPERATOR_CONFIRM=read-only-verified
export PAPER_PORTABLE_WORM_HOSTILE_PHASE=preflight
node pod-provider/backend/scripts/probe-oauth-portable-s3-hostile-lock.mjs
```

Substitute the actual previously approved provider, bucket and receipt
values; for Storj use `https://gateway.storjshare.io/`, and for a
custom S3 origin pin `PAPER_PORTABLE_WORM_APPROVED_ENDPOINT` and
`PAPER_PORTABLE_WORM_REGION` exactly as in the existing read-only
qualification. Do not set `PAPER_PORTABLE_WORM_ADVERSARY_PROFILE`,
`PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE` or
`PAPER_PORTABLE_WORM_HOSTILE_ACK` for preflight.

Preflight requires a **single** exact-version Object Lock receipt
with **no** delete markers, intact canonical content/SHA-256,
versioning, >=400-day default COMPLIANCE, >=32 days of retained
COMPLIANCE lifetime and safe HTTPS transport. It returns a SHA-256
`approvalChallenge` bound to the operator-pinned provider origin,
bucket, key, exact S3 version ID, receipt digest and **observed
retention expiry**. A different version, bucket or retention date
requires a fresh approval. No mutation is issued in this phase.

### Phase 2 — separately approved hostile mutation attempts

**Only after explicit independent operator authorization for the
exact sacrificial version and potential irreversible result:**

```sh
export PAPER_PORTABLE_WORM_OPERATOR_CONFIRM=hostile-locked-version-approved
export PAPER_PORTABLE_WORM_HOSTILE_PHASE=hostile
export PAPER_PORTABLE_WORM_HOSTILE_DISPOSABLE=confirmed
export PAPER_PORTABLE_WORM_ADVERSARY_PROFILE=separate-custody-adversary
export PAPER_PORTABLE_WORM_WRITER_PROFILE=separate-custody-writer
export PAPER_PORTABLE_WORM_HOSTILE_ACK=hostile-locked-version:EXACT_PREFLIGHT_CHALLENGE
node pod-provider/backend/scripts/probe-oauth-portable-s3-hostile-lock.mjs
```

The script performs **exactly one** `DeleteObjectCommand` with the
approved `VersionId`, then independently revalidates the whole
single-version history, exact retained bytes, SHA-256, unmodified
retention and absence of delete markers. It performs **one**
`PutObjectRetentionCommand` for that same version, attempting
to shorten the observed COMPLIANCE expiry by **one day**. It again
requires complete unmodified readback.

There is no SDK or application retry of either mutation, even on
409, timeout, 429, 503 or lost acknowledgment. A returned 200/204,
a changed retention date, a missing version, a new version, an
unexpected delete marker or any ambiguous response **fails**.
Only explicit error-code/status denials are observed. Bounded
exponential backoff with jitter is used **only for idempotent,
read-only `GetObjectRetention` under 429/503/504** (three attempts
maximum). Neither test invokes an unversioned delete, which S3
may legitimately turn into a delete marker even with a COMPLIANCE
protected historical version.

Even when both negative requests receive 400 or 403,
**this alone does not prove COMPLIANCE enforcement**: insufficient
IAM privileges, invalid request serialization, unsupported S3
methods or provider policy may yield identical responses. The
result explicitly keeps `iamEnforcementProven:false`,
`independentAdministrationVerified:false`,
`monotonicLatestHeadVerified:false` and
`releaseAccepted:false`.

### Release evidence and independent-review criteria

A separate human security/custody operator must retain a signed,
tamper-evident **out-of-band certificate** (not just Paper CI
logs) containing the approved account boundary, distinct project
owners/root credentials, sealed KMS/recovery key custody, reader,
writer and adversary rights, positive proof that the adversary had
**permission to attempt exact-version deletion and retention changes**
(therefore 403 is not solely an IAM denial), provider/region,
bucket policy, retained sample key/version/SHA/expiry, both
sanitized negative API responses and timestamps, immutable
version-history snapshots after each attempt, checksum and key
rotation/backup behavior, and auditor approval. Also examine
vendor-native API paths, not only S3 gateway paths, for deleting or
shortening a retained version.

For a deliberate **unversioned** deletion or same-key overwrite
test, use an entirely distinct disposable sample and an independently
approved separate procedure: those operations may create a
delete marker or additional retained version, **which would
invalidate this exact-version sample for authorization purposes**.
Never infer that a COMPLIANCE mode prohibits unversioned delete
markers (AWS documents the contrary). An externally authenticated,
nonrewindable monotonic **latest** generation head is still necessary.

Provider specifications and independent review:
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html
- https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api
- https://www.backblaze.com/docs/cloud-storage-s3-compatible-api-bucket-versions
- https://storj.dev/dcs/api/s3/object-lock
- https://storj.dev/dcs/api/s3/s3-compatibility

**Neither CI fixtures nor a connected Cloudflare account establish
independent administration or real S3 COMPLIANCE custody. Until a
real provider and external operator have completed this protocol
and the monotonic signing authority, the production fuse stays
CLOSED.**
