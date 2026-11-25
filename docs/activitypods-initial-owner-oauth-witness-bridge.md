# Authenticated initial OAuth consent — PG18 / independent witness / Redis admission

**Gate:** NONACTIVATED, disposable only. This is **not** production consent
issuance, a general post-enrollment session implementation, or authorization
to open Paper/Memory signup. Native Solid-OIDC ownership, ActivityPub,
managed ATProto DID and canonical account identity stay with ActivityPods.

## Explicitly separated authorities

| Authority | Function | What it must *not* do |
| --- | --- | --- |
| Authenticated owner browser + enrollment journal | Privately verify the live signed owner session, credential seal and an independently issued enrollment token hash | Infer the owner from a browser-supplied WebID, unsiged JWT, old RS256 bearer or Redis-only enrollment |
| Canonical PostgreSQL 18 | Use the existing **v7** `issue_session_oauth_generation` function on a restricted issuer LOGIN, derive WebID/client/app/SAI from the verified signup journal, and atomically issue **only revision 1** | Accept caller-supplied owner, DID, app, client, ACL selection or a raw unrestricted SQL issuer function |
| Independent witness + immutable archive | Seal and verify the latest exact owner/client/grant/revision receipt, with independent signing/custody, object version, retention policy and an *uncached* fresh high-water read | Trust an ordinary R2 bucket lock, a primary-PG snapshot, an S3 PUT ACK, a stale cached head, or a callback controlled by the OAuth client |
| Redis 8.2 | Persist the first authorized grant only after canonical and independent receipt readbacks, with the existing browser-session Lua CAS | Override PG/witness revocation, approve from a restored session alone, or retry unknown write ACK |

The new `oauth-initial-owner-epoch-issuer.cjs` checks actual PG18 LOGIN
privileges on **every borrowed connection**, and performs its journal-bound
CAS on that *same* connection. It rejects permission inheritance, direct
OAuth-table privilege, role switching, reader/revoker/signer/SAI privileges,
and the legacy raw issue function. It cannot reapprove or revoke a grant.

The new `oauth-initial-owner-consent-coordinator.cjs` receives only an
opaque context from a **provider-held** owner verifier. That verifier must
validate the real HTTP-only signed browser session, current credential
verifier and live Redis session, and independently recover the enrollment
token hash. Browser callers never choose account/app/client or scope. The
coordinator uses an internally minted unpredictable generation ID and a
single pinned, narrow feed-post-create scope.

Order for first issuance:

1. Verify live owner + the separate enrollment proof.
2. Issue canonical PG revision 1 through restricted v7 session function.
3. Read the exact managed owner/SAI/scope/grant tuple from restricted primary
   PG, then attest the independent WORM epoch, and read *both* again.
4. Verify the same live owner/credential/enrollment proof again. Only then
   run the existing Redis session-guarded Lua SET, atomically serialized
   against browser logout. A changed or expired session does not persist
   consent.
5. Read current canonical PG and independent latest witness again before
   returning consent evidence. Token/code minting must continue checking
   both on *every* admission, including after Redis and PG rollback.

No ambiguous PG, WORM, or Redis write is automatically retried. A lost
acknowledgement can leave a canonical revision or a Redis record behind:
those require **operator reconciliation**, not browser-side replay or
silent reapproval. A materialized Redis grant never supersedes either
PG or independent high-water denial.

## Adversarial test coverage and limitations

`tests/oauth-initial-owner-consent-bridge-node.test.cjs` covers exact role
privilege denial, every new connection rechecking roles, invalid scope/hash,
ambiguous SQL and Redis acknowledgements, owner logout/credential change,
witness outage and stale head, concurrent first issuance and post-CAS
revocation. The real-Redis variant executes the existing Lua transaction on
**Redis 8.2** with binary DUMP/RESTORE, and passes an ES256 access token
through the real OAuth introspection handler. Old Redis state and a simulated
canonical PG rewind remain denied by a simulated independent latest-head
reader. The existing separate two-cluster PG18 witness workflow still owns
the **real** canonical/witness SQL rollback proof. No user accounts,
external immutable bucket, non-synthetic owner or production password is
used by this test.

**What is not yet achieved:** The current signed-in OAuth browser session is
not the v7 signup enrollment hash. These are different credentials and must
*never* be treated as interchangeable. There is not yet an implemented
provider-held verifier combining a real signed-in session with PostgreSQL
post-enrollment consent intent and native Jena SAI reattestation. The
coordinator's privately injected owner/PG/WORM callbacks are disposable
contract fixtures, not runtime-wired production services.

Also **not supported** here: reapproval, scope expansion, revoke, uninstall,
or password-rotation completion. A correct new consent authority requires
an independently archived **pre-transition deny intent** before replacing
or revoking an existing grant. Otherwise a PG PITR and Redis restore
between primary commit and immutable witness sealing could resurrect the
old still-signed credential. Simply doing PG-first-then-WORM is not a safe
general revoke protocol. Any failed or ambiguous revocation attempt must
remain denied until independently reconciled.

## Gates before production activation

- Implement authenticated post-enrollment owner session/credential epoch
  admission in canonical PG with exact Session/CSRF/SAI binding and
  independent native Jena permission readback, ensuring credential rotate,
  logout, group-rights downgrade and cross-owner IDOR fail closed.
- Implement independent WORM **pre-transition denial intent** and explicit
  commit/abort reconciliation, with no cached or rewindable allow result.
- Deploy an independently administered S3-compatible Object Lock
  **COMPLIANCE** archive (not AWS-specific), independently protected latest
  signer, disjoint writer/reader/retention/admin roles, proven hostile
  overwrite/delete/shorten/multipart/conditional-creation behavior.
- Run true *physical* PostgreSQL + Redis + Jena + PDS rollback/crash,
  partition, reconnect, multi-worker, slow ACK and concurrent owner
  approve/revoke tests with real service identities.
- Rotate any historically committed secrets, audit image artifacts,
  verify old sessions/JWTs rejected, then separately complete positive
  unified-account browser/Solid/ActivityPub/ATProto signup and independent
  security/performance acceptance.

**Release remains `CLOSED` and the code must not be imported by
running services.** A passing disposable test proves an isolated invariant,
not deployment custody, owner proof or production admission.
