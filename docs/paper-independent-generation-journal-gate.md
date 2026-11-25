# Independent authorization generations: dual-status S3 WORM recovery gate

**NONACTIVATED candidate, November 25, 2026. Production release remains CLOSED.**

This is an ActivityPods **unified account** authorization protocol, shared by
Paper/Memory and the federation sidecar. It is not a new account database,
a replacement for Solid-OIDC/SAI, or an ordinary S3 object media pipeline.

## Security objective and exact implementation

Source: `pod-provider/independent-authority/oauth-generation-worm-journal.mjs`

The historical PRE-DENY-only signer has been extended *by a separate
candidate*, not weakened, with a durable, cryptographically hash-linked
generation journal for **one independently observed ACTIVE genesis and
one terminal BLOCKED transition**. The object key format is
`paper/oauth-authority/generations/v1/<64hex-signed-v5-subject>/<19-digit-sequence>`.
Receipts use the existing `assertReceipt` validation and have a
strict schema, canonical UTF-8 bytes, maximum 1024 bytes, a recorded
legacy epoch-v1 NUL-framed subject digest **explicitly distinct** from
the v5 subject digest, stable grant/scope/owner-proof hashes,
canonical OAuth/credential/SAI revisions, UUID operation, previous
SHA-256 receipt hash, and for BLOCKED the exact PRE-DENY v7 WORM
receipt SHA-256. No raw credentials, OAuth refresh tokens or private
signing material are placed in S3.

The independent reader performs S3 versioning and default COMPLIANCE
retention checks and a complete, bounded `ListObjectVersions`
with no truncation or delete marker. It locally sorts entries by
**numeric** sequence, rejects duplicate versions, missing numbers,
unexpected object keys, forks, zero or overflowing counters and
malformed content. For each entry it independently GETs exact version,
checks canonical hash-linked receipts and reuses the existing strict
S3 Object Lock inspector for independent HEAD, retention, complete
object-version history, GET digest and bucket policy. The sequence
must begin at 1, preserve owner/client dual subject binding, and
transition ACTIVE -> BLOCKED exactly once. A terminal BLOCKED must
also correspond to the *independently retained* PRE-DENY v7 receipt,
matching operation ID, grant, revision and digest. A second complete
inventory must agree with the first.

The independent append adapter is test-only. It verifies the current
journal and relevant PRE-DENY before writing, requires an SDK-configured
single attempt for read and write clients, and uses a conditional
`PutObject If-None-Match:*` on a uniquely numbered key. After either
a 412 or lost-ACK, it **never retries**, instead reconciling the exact
object version, content hash, canonical chain and PRE-DENY readback.
A failed reconciliation, duplicate object version, unexpected ACK
version or competing head is refused.

Every possible response, including a successfully recovered ACTIVE
genesis, explicitly states `activeAuthorizes:false` and
`releaseAccepted:false`. Neither the journal nor denial signer is
imported into the ordinary ActivityPods service tree.

## State machine — intentionally narrow

```text
no retained journal --[owner-certified genesis]--> ACTIVE, generation 1
ACTIVE generation 1 --[independently prepared + sealed PRE-DENY]-->
BLOCKED, generation 2 (terminal)
BLOCKED --[anything in v1]--> REJECT
```

The journal checks both subject fields for canonical hash format and
immutability, **not their mathematical derivation from the same WebID and
client ID**. That cross-domain identity mapping must be verified by the
actual authenticated provider and independent custodian before release.

The genesis' `ownerProofSha256` is opaque **evidence metadata**, not a
verified owner session or approval. The actual owner-consent ceremony
must originate from the independently authenticated Solid-OIDC/SAI
provider and cannot be supplied as an arbitrary browser hash. This
module does NOT issue or validate such authentication. Until the live
bridge and separate authority are complete, even a perfect genesis
proves **nothing** about the current credential permission.

The single terminal transition is intentional. Later grant reapproval
and repeated deny cycles need a separately designed versioned protocol
that preserves historical PRE-DENY operations. Existing v7 PRE-DENY
inventory accepts only one operation per subject, so silently enabling
a second ACTIVE would allow a future revoke to lack an authoritative
history. BLOCKED stays terminal in this version.

## Recovery / concurrency threat model

- **PG18/witness/Redis/Jena/PDS/signer PITR:** Previously retained
  BLOCKED remains visible from independent WORM. A recovered ACTIVE
  is explicitly never token-issuance authority.
- **Concurrent writer contenders:** same-key `If-None-Match:*`
  contention is reconciled by exact immutable bytes and version
  history; two versions or a different operation are rejected.
  A caller cannot jump to revision 3 or overwrite a terminal denial.
  **S3 is not itself the independent sequencer**, and conditional
  PUT is not an inter-resource transaction lock.
- **Missing, corrupted or hidden history:** reject observable gaps,
  forked versions, delete markers, conflicting receipts, insufficient
  retention and mid-read changes. A malicious backend may show a
  *coherent but stale* prefix and return `IsTruncated:false`;
  the reader cannot detect that without independent signed
  high-water. This is explicitly tested: stale ACTIVE still has
  `activeAuthorizes:false`.
- **Storj listing order:** official Storj docs say encryption can
  defeat plaintext lexicographic listing order. This implementation
  requires a bounded, nontruncated single inventory page and sorts
  locally, never infers numeric latest from returned order.
- **Retention expiry:** bucket default >=400 days and per-object
  remaining >=30 days are checked. No 400-day retention window is
  permanent; a separately certified checkpoint renewal and permanent
  reference must exist *before* the oldest genesis could expire.
- **External signing key:** the existing nonce-bound ED25519 denial
  signer remains separate. This journal does not add an ACTIVE
  signing mode, a KMS owner, an HTTP endpoint, or a private key.

## Remaining production gate, not accomplished by this PR

1. Provision and certify **independent** human-operated S3-compatible
   COMPLIANCE custody (Backblaze B2, Storj when supported, or another
   qualified provider) with separately governed credentials, root,
   billing, disaster recovery, and scoped read/write/lock management
   roles. The currently connected Cloudflare account and R2 bucket
   locks alone do **not** qualify.
2. Demonstrate on a disposable live bucket genuine
   `If-None-Match:*` concurrency (including delete marker), refusal
   of direct version delete, overwrite and retention shortening,
   original and historical exact-version readback and lost-ACK
   reconciliation, without automated retry.
3. Deploy and certify a genuinely **nonrewindable externally
   authenticated sequencer and monotonic latest-head signer** with
   key custody independent of ActivityPods, PG, Redis, Jena,
   federated actors and Paper deployment administration. The
   externally signed checkpoint must be fresh, nonce-bound, cover
   both epoch-v1 and generation-v5 subject mappings, and survive
   signer key rotation, PITR and account compromise.
4. Wire live canonical Solid-OIDC/SAI owner consent and revocation
   through independent PG18 v7 PREPARE/SEAL/WRITE-COMMIT fencing to
   code issuance, DPoP, access JWTs, refresh, signed ATProto/PDS
   reservation/commit and both federation sidecars. Require real
   physical recovery of BOTH PG18 stores, Redis/Jena/PDS and the
   independently hosted signer. Demonstrate revoked tokens, old
   generations and stale signer proofs cannot be admitted.
5. Positive hosted end-to-end signup, performance and independent
   security/operator signoff. **Release CLOSED until all pass.**

## Evidence and references

- Test: `pod-provider/backend/scripts/proof-oauth-generation-worm-journal.mjs`
- CI: `.github/workflows/paper-oauth-s3-compliance-archive.yml`
- Existing denial signer: `pod-provider/independent-authority/immutable-denial-head-signer.mjs`
- AWS Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- AWS conditional-write delete marker semantics: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
- AWS WORM key/retention limitations: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html
- Backblaze B2 S3 lock: https://www.backblaze.com/docs/cloud-storage-enable-object-lock-with-the-s3-compatible-api
- Storj S3 listing: https://storj.dev/dcs/api/s3/s3-compatibility
- Storj managed-encryption listing: https://storj.dev/dcs/api/s3/s3-compatibility/storj-vs-self-managed-encryption-s3-compatibility-differences

No source of authority in the ordinary provider changed; no live
credentials or external custody were provisioned.
