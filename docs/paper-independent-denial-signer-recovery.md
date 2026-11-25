# Independent signer reconstruction from Object Lock PRE-DENY evidence

**Status: NONACTIVATED custody-side implementation, not independently
administered live infrastructure. Production OAuth/PDS and signup stay CLOSED.**

## Boundary / drift audit

This is an ActivityPods unified-identity authorization dependency, shared by
the Paper or Memory application and its federation sidecar. It is **not** an
application-branded login mechanism, a Mastodon-only feature, or a replacement
for SemApps/Solid-OIDC/SAI. Do not move canonical owner or grant authority
out of ActivityPods, change the signed-PDS state machine, weaken the v7
PG18 PREPARE row lock, or substitute Cloudflare R2 bucket locks for genuine
COMPLIANCE immutable retention.

Source `pod-provider/independent-authority/immutable-denial-head-signer.mjs`
intentionally lives **outside** the ordinary backend services tree.
It accepts only a nonce-bound `paper.oauth.pre-deny.challenge.v1` for a
pseudonymous **v5 length-framed** owner/client subject SHA256. It reuses the
real S3-compatible API read-only inventory introduced in ActivityPods #320:

1. Perform fresh, bounded independent Object Lock COMPLIANCE bucket, version,
   exact retention, canonical receipt, SHA256 and history verification.
   Refuse missing, incomplete, conflicting, marked-deleted or malformed
   receipts. An empty listing is **never** an ACTIVE statement.
2. Extract the exact retained `subject`, `revision`, `grantSha256`,
   `operationId`, `receiptSha256` and opaque storage version; no browser
   WebID, grant ID, token, session or unrelated user profile is sent
   to the external signer.
3. Construct deterministic, canonical
   `paper.oauth.pre-deny.head.v1` bytes with the client's fresh 256-bit
   random nonce, a strictly bounded clock and pinned authority name.
4. Have a distinct privileged **signing callback** sign the Ed25519
   domain-separated bytes. The code accepts only a pinned PUBLIC key,
   independently verifies the resulting 64-byte signature, and exposes
   no private-key injection, export, HTTP listener, production key or
   automatic fallback.
5. **After** signing, repeat the entire independent archive verification.
   Do not expose the signature if the object disappeared, changed
   versions or digests, the policy weakened or the history was truncated.
   Refuse an aborted challenge and all production/test-gate bypass.
6. Only then return a `denied:true` statement that the existing
   `oauth-pre-deny-signed-head.mjs` consumer independently verifies,
   including exact subject, grant hash, revision, operation UUID, receipt
   digest, new nonce, Ed25519 signature, canonical bytes and clock.

The authority holds **no** mutable authorization cache or signer-local
latest-row pointer. A simulated rollback of signer, Redis, canonical PG and
witness PG therefore cannot make this one-way denial statement ACTIVE:
fresh PRE-DENY WORM evidence is required on **every** challenge.

This is more substantial than a synthetic signed response fixture:
the new adversarial test actually follows the S3 command-shaped custody
reader, exact object-version/retention/receipt validator, Ed25519 signature
generation callback, and the preexisting client-side signature verifier.
CI also repeats it using pinned real AWS S3 SDK command constructors.
The S3 service, private signing service and separate operator are still
**test doubles**, not live third-party infrastructure.

## Explicit limitations: no false production claim

This is a **one-way DENIAL signer**. It will never issue ACTIVE, approve a
login, set `releaseAccepted:true`, certify a compliant S3 account, or
authorize a signed-PDS commit. It does not create, erase or amend receipts.
No endpoint has been deployed in the provider or federation services;
external private signing material and storage principals are NOT provisioned.

COMPLIANCE protects retained **object versions**, not necessarily the
current key: a DELETE may create a marker. An S3 `If-None-Match:*` write
can also succeed against a current delete marker, and Object Lock alone
is **not** a distributed lock. The reader rejects all observed delete
markers and duplicate versions. Those observations cannot prove an
untrusted provider is showing complete, latest state.

**Provider drift discovered 2026-11-25:** Storj's S3 compatibility
documentation explicitly warns that object listings may not be in
lexicographic order, so a cross-provider ordered pagination/checkpoint
algorithm is unsafe without provider-specific measured proof. This
candidate accepts at most **one** retained PRE-DENY version under an
exact subject prefix and rejects truncation; it makes no positive
claim about a paginated global high-water or Storj concurrency.

Object Lock default retention of 400 days does NOT provide indefinite
denial protection. Before expiry, the external custodian must establish
and test a durable renewal/high-water chain and independent
nonrewindable head authority that survives *both* physical signer
PITR and provider/archive-specific failover. A malicious custodian or
stale/incomplete `ListObjectVersions` still defeats a read-only
observation. Never count local cached active state as a fallback.

The signer must ultimately be deployed behind independently
authenticated/mTLS or equivalent service-to-service identity, strict
rate limiting, KMS/HSM held **outside** ActivityPods, independent audit
logs, key rotation and access revocation. Never offer its hash-prefix
lookup to arbitrary public clients.

## Required outside-custody release acceptance

1. Obtain a **separately administered** B2, Storj or independently verified
   S3-compatible Object Lock COMPLIANCE environment with physically
   independent operator/root/recovery, billing, key management and
   retention policy. No assumption of AWS-only account IDs.
2. Prove real `If-None-Match:*` contention, failed/lost PUT ACK recovery
   without silent retries, complete version inventories, refused
   overwrite, direct-version DELETE and retention truncation, marker
   visibility, and retention >=400 days. A sacrificial isolated
   test bucket is necessary; never test destructive behavior on customer
   authorization records.
3. Deploy the independent **positive and negative** monotonic
   high-water authority, create/write/genesis and revoke/replace
   protocols, revocation prepare-v7 serializable fence, durable signed
   PDS intent resolution, cross-domain v1/v5 account subject mapping,
   and current-head checks on all actual Solid-OIDC/SAI/OAuth/PDS paths.
4. Crash/partition, concurrent writer, whole-witness and canonical
   PG18 **physical** PITR, Redis/Jena/PDS restore, signer re-provision,
   old signer-key replay and cloud archive disaster recovery.
   Demonstrate all restored pre-denial credentials remain refused.
5. Real hosted positive owner-consented signup, cross-protocol WebID /
   ActivityPub / DID PLC / signed PDS write-read, denied revoked
   refresh/session/JWT/DPoP, performance under contention, and
   external operator and security reviewer signoff.

## CI evidence and external primary references

Test: `pod-provider/backend/scripts/proof-independent-denial-head-signer.mjs`
Workflow: `.github/workflows/paper-oauth-s3-compliance-archive.yml`
Production service import guards must remain active. All reports must
retain `releaseAccepted:false`.

Relevant primary documentation:

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html
- https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api
- https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
- https://www.backblaze.com/apidocs/s3-put-object
- https://www.backblaze.com/apidocs/s3-delete-object
- https://storj.dev/dcs/api/s3/s3-compatibility
- https://storj.dev/dcs/api/s3/object-lock
- https://storj.dev/dcs/api/s3/credentials

**Do not open signup or activate the signer with mock, same-account or
R2-only results. Keep P0 OPEN.**
