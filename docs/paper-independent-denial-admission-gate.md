# Independent PRE-DENY current-head admission — production P0 handoff

**Status: NONACTIVATED candidate. Production signup and PDS OAuth issuance remain CLOSED.**

This checkpoint continues merged #314 (certified authenticated owner/grant),
#315 (pre-denial Object Lock receipt + independently signed head contract),
and #316 (byte-exact PG18 signed-intent/pre-deny subject correlation).

## Implemented in this change

`oauth-independent-pre-deny-admission.mjs` is a **test-only, read-only
verifier** that can inspect the authorization boundary of 15 explicitly
enumerated OAuth, DPoP, signed-PDS and owner-grant operations. It **cannot**
approve any mutation, token, authorization code, refresh or signed repo
commit; its response always contains `releaseAccepted:false`.
No live service imports it. `NODE_ENV=test`, disposable environment flags
and `fixtureOnly=true` are necessary even to construct it.

The caller supplies only a *surface* name and opaque request context.
The trusted provider-held `authenticateGrant` adapter must authenticate
the actual browser cookie + Redis session + password/credential epoch for
owner interactions, or validate the actual signed access/refresh token and
DPoP binding for the applicable OAuth/PDS interaction. Its output must be
derived from provider state, **not** request-selected WebID, grant ID,
client ID, owner, credential epoch or externally supplied public key.

For every inspect invocation, this candidate checks:

1. **Authenticated exact grant:** WebID, client, unpredictable grant ID,
   consent scope SHA256, OAuth epoch, native SAI revision, credential epoch,
   and a hashed authentication-proof identifier; strict HTTPS and revision
   grammar. The provider must separately attest DID / WebID mapping and
   native Jena/SAI permission freshness before returning this proof.
2. **Current canonical ActivityPods PostgreSQL:** existing unified account
   and owner permission/grant state, with exact correlation and no
   caller-provided scope. Pending credential rotations must refuse.
3. **Current independent PostgreSQL 18 witness:** active, sealed, exact
   grant hash, revision, event SHA256 and immutable receipt correlation.
4. **Independently verified immutable latest archive:** exact event,
   grant, revision and status, complete version history, specific retained
   version and independent Object Lock readback. The *injected* callback
   must substantiate these claims under a separate principal; Boolean
   fields from an application-owned callback are NOT evidence of custody.
5. **Fresh nonce-signed Ed25519 latest-head response:** pinned public-only
   key; strict canonical bytes, domain separation, subject, revision,
   receipt SHA256, witness digest, signing-authority ID, nonce and bounded
   signing-time skew. A signed BLOCKED head or historical replay denies.
6. **Recheck canonical, witness, archive and the same authenticated proof**
   after network reads. Revoke, credential/password change, witness epoch
   change, role/session loss, SAI change, retention loss and WORM change
   during the check deny. There is no positive-result cache or retry of
   unknown external writes.

**Two subject encodings are deliberately distinct**, to avoid silently
mixing records introduced under different historical contracts:

* Witness **epoch-v1** S3/Object Lock records are SHA256 over
  `paper:witness:subject:v1\0<owner>\0<client>`.
* Independent witness **signed-write v5** and pre-denial-v1 use SHA256
  over `paper:witness:subject:v1:<owner-character-count>:<owner>:<client>`.

The new candidate requires BOTH subject hashes, signs BOTH in its
fresh current-head statement and compares them across independently
read archive and witness claims. That documents and tests the historical
difference, but **does not automatically unify the independently
administered latest-head indexes**. A final operator-owned signer must
establish a single monotonic correlation mapping across these domains
before a real release.

### Enumerated admission surfaces

| Surface | Existing code / necessary future enforcement |
| --- | --- |
| `authorization-code-issue` | `oauth-authorization.service.js` and `oauth-code-store.service.js` before any code/consent state |
| `authorization-code-redeem` | `oauth-token.service.js` before consuming the code |
| `access-token-sign` | `oauth-token.service.js` before accessing signing key and immediately before signature |
| `access-token-introspect` | `oauth-token.service.js` on every access token verification, including restored tokens |
| `refresh-token-issue` | `oauth-refresh-session.service.js` before inserting a refresh family |
| `refresh-token-rotate` | Same service before rotating family state |
| `refresh-token-introspect` | Same service before reporting a refresh token as active |
| `dpop-protected-resource` | DPoP verifier + protected resource adapter before repository access; proof `ath` and `jkt` must match |
| `signed-pds-reserve` | Witness-backed PDS writer before reserving a signed intent |
| `signed-pds-commit` | PDS writer, with canonical consent `FOR SHARE` and independently sequenced denial/writer reservation |
| `owner-consent-approve` | Current signed browser session + fresh native SAI before approval |
| `owner-consent-revoke` | PRE-DENY retained and latest-head fence before primary revoke |
| `owner-consent-replace` | PRE-DENY retained before new generation, old generation never reactivated |
| `owner-app-uninstall` | Same as revoke, including native SAI and token-family invalidation |
| `owner-grant-session-admit` | Existing signed browser credential epoch and native SAI after independent deny check |

**The table is an implementation inventory, NOT evidence of runtime
installation.** The runtime services still use their source-controlled
`PDS_OAUTH_RELEASE_GATE_CLOSED` branch; the candidate does not
turn on these surfaces.

## Tests

The isolated deterministic proof runs all 15 surfaces and asserts
exactly two authenticated/canonical/witness/archive observations plus a
fresh signature for each. It rejects wrong/synthetic request selectors,
revoked or rewound PG/witness/immutable archive, partial version history,
missing COMPLIANCE evidence, issuer replay, cross-subject hash confusion,
wrong or private Ed25519 key, incorrect nonce/grant/revision/digest,
expired/future signature, session logout, password rotation, SAI revocation,
witness change mid-read and bounded network timeouts. CI also reruns the
existing two-PostgreSQL-18 witness proof, S3 mock command contracts,
backend tests and lint. These new `read*` adapters are **test doubles**.

## Required before claiming production completion

1. An independently administered, separately credentialed, **nonrewindable**
   monotonic latest-head signer and retrievable retained Object Lock
   COMPLIANCE receipts (>=400 days per currently selected release policy),
   with operator-proven conditional create-only, history and deletion
   resistance, including account deletion/administrative separation.
2. A single independently retained correlated subject map across epoch-v1
   and signed-write v5/PRE-DENY, protecting against malicious PITR of
   canonical PG, witness PG, Redis, Jena and the signer itself.
3. Real provider-side owner/session/credential and native SAI integration;
   *actual* token, refresh, code, DPoP and signed-PDS endpoints MUST invoke
   independent deny admission before side effects and after recovery.
4. An **atomic grant-use fence** across signer and canonical PostgreSQL:
   a network read of an ACTIVE head can race a PRE-DENY publication. The
   PDS writer must durably reserve/retain PENDING before repo COMMIT, settle
   its COMMITTED receipt after independent signer/CAR/outbox proof, and hold
   canonical owner/SAI/credential locks. The revoker must drain and witness
   **all** outstanding intents before acknowledging owner revocation.
   A lost ACK never automatically aborts or allows an old token to revive.
5. Real full-circle owner grant/reapprove/revoke/uninstall lifecycle,
   physical multi-store backup/restore fault injection, independently
   reviewed privilege separation/secret rotation, hosted positive unified
   signup, performance/scale signoff and operator incident recovery.

The repository must NOT open production signup or PDS OAuth on the basis
of a passing mocked signer, synthetic WORM read, or a fresh signed ACTIVE
response without a durable transactional synchronization protocol.
