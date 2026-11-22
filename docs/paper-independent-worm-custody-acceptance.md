# Paper independently operated S3 Object Lock custody acceptance

**Status: NONACTIVATED operator acceptance, NOT production approved.**
The source-controlled signup release and federation staging release remain CLOSED.

## Purpose and acceptance boundary

A restored PostgreSQL primary, PostgreSQL witness, Redis, and Jena may
agree on an outdated OAuth owner consent. An independently administered
immutable high-water is necessary to distinguish a restored old snapshot
from the real latest authorization generation. A historical retained
receipt alone does NOT prove the archive returned the newest one.

The existing OAuth S3 adapter remains test-only. It now adds the
independently expected AWS bucket owner account ID to EVERY S3 command,
including bucket lock/versioning, full version history and per-version
retention reads, and conditional PUT. Invalid or missing IDs refuse.

The new read-only AWS custody probe performs independent STS caller
identity checks, S3 versioning and Object Lock COMPLIANCE inspection,
bucket-level public access block, and optional exact-version readback
of an out-of-band supplied epoch receipt. It NEVER makes writes,
deletes, or Object Lock policy changes and ALWAYS reports
releaseAccepted:false. It is an evidence collector, not a release switch.

## Required separate administrative boundaries

1. An archive AWS account with its own administrator, recovery, billing,
   root and AWS Organizations access must not be controlled by the Paper
   provider's deployment or app operators. Do not use an R2 bucket lock
   under the same Cloudflare account as an independent COMPLIANCE archive.
2. The archive owner must create a standard Amazon S3 bucket with S3
   Object Lock enabled, versioning Enabled and default retention in
   COMPLIANCE mode of at least 400 days; configure all four S3 bucket
   Block Public Access flags. Establish independent audit/CloudTrail
   retention, lifecycle controls and encryption-key continuity.
3. A provider-account restricted writer role may only create objects
   under the narrow paper/oauth-witness/ prefix with conditional PUT.
   It cannot delete versions, modify lifecycle/retention/policy or
   administer the external account. Never share writer credentials
   with reader/reviewer or internal PostgreSQL/Solid/SAI keys.
4. The archive-account read-only role needs S3 bucket permissions
   GetBucketVersioning, GetBucketObjectLockConfiguration,
   GetBucketPublicAccessBlock and ListBucketVersions; exact object
   version/retention permissions GetObject, GetObjectVersion and
   GetObjectRetention; and STS GetCallerIdentity. Separate trust
   policies and resource-ARN scoped bucket policies are mandatory.
5. A distinct human security custodian must review live IAM roles,
   trust relationships, AWS Organizations/SCP and account-close
   controls, bucket policy, retention history, object versions,
   lifecycle, signing-key availability, recovery and audit logs.
   STS identity shows account and role but cannot certify that
   two AWS accounts are independently administered.

References:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html
https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-owner-condition.html
https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html
https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html

## Read-only real AWS account and bucket preflight

Install the three exact AWS SDK v3 packages OUTSIDE the application
checkout. Never paste keys into source, CI logs or chats. Both
profiles must be configured locally with distinct IAM role identities.
The test proof uses fake transport; the operator CLI uses actual
AWS SDK and real named-account credentials.

```sh
mkdir -p "$HOME/.local/share/paper-worm-sdk"
chmod 700 "$HOME/.local/share/paper-worm-sdk"
npm install --prefix "$HOME/.local/share/paper-worm-sdk" \
  --save-exact --ignore-scripts --no-audit --no-fund \
  @aws-sdk/client-s3@3.1174.0 \
  @aws-sdk/client-sts@3.1174.0 \
  @aws-sdk/credential-providers@3.1174.0

export PAPER_WORM_SDK_ROOT="$HOME/.local/share/paper-worm-sdk"
export PAPER_WORM_CUSTODY_OPERATOR_CONFIRM=read-only-verified
export PAPER_WORM_PROVIDER_PROFILE=paper-restricted-writer
export PAPER_WORM_READER_PROFILE=paper-independent-archive-reader
export PAPER_WORM_PROVIDER_ACCOUNT_ID="<the-real-provider-account-id>"
export PAPER_WORM_ARCHIVE_ACCOUNT_ID="<the-real-archive-owner-account-id>"
export PAPER_WORM_BUCKET="<independent-s3-bucket>"
export PAPER_WORM_REGION="<actual-aws-region>"
export PAPER_WORM_CUSTODY_PHASE=preflight
node pod-provider/backend/scripts/probe-oauth-independent-s3-custody.mjs
```

The probe forces the public AWS commercial-partition regional HTTPS
STS and S3 endpoints. It refuses custom endpoint URLs, alternate CA
bundles and disabled TLS verification, rather than accepting a mock
service or a redirected SDK profile as real AWS custody. AWS GovCloud
and China partitions need an independently reviewed endpoint policy
before being supported. This does not replace operator review of
trusted machine TLS roots or cross-account IAM role trust.

The preflight checks actual, independent STS account IDs and restricts
caller identities to IAM roles rather than root or IAM users. Every S3
request carries the expected archive bucket owner. The command refuses
non-AWS custom endpoints, missing credentials, weak default retention
or missing bucket-level public-access blocks. There are NO PUT/DELETE
commands. A green preflight reports configurationVerified true but
receiptVerified false and releaseAccepted false.

## Exact receipt readback, independently provided by the custodian

The independent witness attestor must first deposit a genuine canonical
epoch receipt under COMPLIANCE and record its S3 VersionId, exact key
and SHA-256 outside ALL restored databases. The operator must approve
that long-lived immutable write separately. The read-only probe cannot
create the receipt or fake its digest.

```sh
export PAPER_WORM_CUSTODY_PHASE=receipt
export PAPER_WORM_RECEIPT_KEY="paper/oauth-witness/epochs/v1/<64-lower-hex>/<19-digit-revision>"
export PAPER_WORM_RECEIPT_VERSION="<exact-object-version-id>"
export PAPER_WORM_RECEIPT_SHA256="<out-of-band-64-lower-hex>"
node pod-provider/backend/scripts/probe-oauth-independent-s3-custody.mjs
```

The reader checks ListObjectVersions for this exact key; extra
historical versions, delete markers, truncated responses and
unexpected versions refuse. It then checks HeadObject,
GetObjectRetention COMPLIANCE through at least 30 more days, exact
GetObject body <=1024 bytes, canonical receipt JSON, immutable SHA-256
and current version again, with bucket policy/versioning rechecked.

The report MUST still say releaseAccepted:false: a verified old
version is not proof of the latest global authorization epoch,
fully restricted IAM rights, real multi-cluster restore ordering, or
production signed-PDS/SAI consent integration. Independent complete
version-history discovery and out-of-band inventory corroboration
remain critical.

## Remaining P0 acceptance after live custody verification

- Live restricted WORM writer, witness SQL attestor, and archive reader
  must produce and confirm immutable pending and resolved PDS-intent
  receipts, owner grant and revocation epochs, including lost ACKs,
  before acknowledging a signed write or grant. The provider may not
  hold privileged witness writer/recovery credentials.
- Real primary and witness PG18 physical base backup plus archived WAL
  PITR to before/after consent and signed write, independently restored
  Redis/Jena and DID/repo state, failover and crash-injection.
  Revocations must remain denied against the latest independently
  retained WORM epoch under every recovered combination.
- SemApps bearer credential/refresh token revocation epochs must be
  persisted in protected canonical authority, not limited to public
  OAuth browser consent. Solid/SAI grants, PG, Jena and PDS signed
  mutations need an attested serializable cross-store state machine.
- Real hosted positive new-user WebID, Solid-OIDC/SAI grant readback,
  ActivityPub remote delivery, did:plc and signed PDS/XRPC write/read
  after owner consent, plus cross-replica post-revoke denial.
- Independently attributable human security and deployment review,
  with IAM, disaster recovery, cross-protocol, credential/token and
  privacy acceptance recorded on the P0 issue.

Keep production and staging CLOSED until all mandatory tests and
operator attestations actually exist. Do not substitute disposable
S3 mocks, R2 removable bucket locks or repeated negative signup
tests for positive release acceptance.
