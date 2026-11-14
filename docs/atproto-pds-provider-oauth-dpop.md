# ActivityPods managed PDS write authorization — provider OAuth and DPoP

**Status: NONACTIVATED proof. No production signup, PDS write route,
or storage release switch is enabled. Existing accounts are not migrated.**

This gate connects the existing ActivityPods OAuth services to the
non-activated signed-PG repository write gateway. It does NOT introduce
a second identity provider, new JWT signer, second consent database, or
new repository writer.

## Trusted services reused

1. `oauth-token.introspectAccessToken` cryptographically verifies JWT
   signature, issuer, audience, expiry, issuer-configured algorithm and
   the exact `at+jwt` **access-token type** using the provider's JWK.
   Other issuer-signed JWT types (including ID/session tokens) are not
   authorization credentials for the PDS, even if they share a key,
   subject and audience.
   Only its output may identify the DID subject, canonical WebID,
   OAuth client and token-bound `cnf.jkt`.
2. `oauth-dpop-nonce.verifyProof` verifies a signed public P-256 JWK,
   DPoP `htm`/`htu`, `jti`, clock skew and JWK thumbprint. The new
   optional protected-resource mode **requires** a SHA-256 base64url
   `ath` of the exact access token, a server-minted nonce and the
   token-bound `cnf.jkt`. Redis 8.2 `GETDEL` atomically consumes the
   nonce across replicas and `SET NX` detects `jti` replay. The
   JTI's replay TTL is at least 660 seconds, exceeding the accepted
   ±300-second proof clock-skew window. Existing token-exchange callers
   remain compatible; they do not have an `ath` before token issuance.
3. `oauth-consent.get` checks the current account/client OAuth consent
   (Redis). The exact client ID is mapped to a fixed, provider-approved
   app URI. The map cannot be supplied in an HTTP request.
4. `paper_atproto_authority` remains the canonical PostgreSQL
   managed-identity and SAI grant authority. The candidate reads its
   existing `getConsent({owner,app})` contract (DID, grant URI,
   active/blocked state and monotonic revision). The signed repository
   writer takes `FOR SHARE` locks on that SAME consent in the commit
   transaction. Jena/Fuseki cannot override a blocked grant.

## Collection/action permission

The `atproto` OAuth scope by itself is **not** a write grant. This
restricted candidate accepts only direct `repo` permission strings
with exact collection or `*` match and the required operation. It
supports the three `create`, `update`, `delete` action constraints,
including repeated `action` and `collection` parameters in a direct
scope. For the transitional `putRecord` method (which may create
or update), the restricted gateway conservatively requires BOTH
create and update authority. No `include:` permission-set expansion or
`transition:generic` privilege is inferred: they remain unavailable
until a trusted permissions resolver is added and tested.

The HTTP `Authorization` scheme is now **DPoP**, not Bearer. One
signed DPoP proof is checked and consumed at the start of a write.
After the signed PG commit and protected projection, the gateway calls
a short-lived, provider-created `recheck()` closure on that very
authorization result. It re-introspects the token and rereads OAuth
consent + canonical PG grant but **does not re-verify the consumed DPoP
proof**, which would fail with a false replay after a valid write.
If a revocation occurs between the signed commit and HTTP response,
HTTP returns a generic unavailable result and the client must
reconcile the signed head using `swapCommit`; no blind retry or
duplicate write is allowed.

## Acceptance

The backend CI runs a **real Redis 8.2.11** isolated service, not a
mock replay dictionary. The proof directly invokes the existing
provider JWT issuance/introspection, DPoP signature verifier,
OAuth-consent service and the new authorization bridge. Tests cover
issued signed JWTs, P-256 DPoP proofs, `ath` token substitution,
issuer/audience/client mismatch, missing nonce, signature/HTU/HTM
errors, granular repo permissions, consumed nonce + reused jti,
atomic concurrent nonce consumption and canonical OAuth/SAI consent
revocation.

A separate HTTP acceptance invokes the existing PDS XRPC gateway
with real provider cryptographic authorization and a disposable
signed-repository writer stub to prove one DPoP use across the
post-commit recheck and refusal of a replayed write. The existing
PostgreSQL 18 + upstream MST tests independently prove real signed
record, canonical grant lock, outbox, projection and concurrent revoke.
Combining these test boundaries on a real provider is still a
production release requirement.

## Release blockers

- This bridge is deliberately not autoloaded, not HTTP routable in
  production and refuses `NODE_ENV=production`. The callback `call`
  must only be supplied by the trusted ActivityPods broker, never by
  an API request; `readCanonicalGrant` must use the restricted
  canonical PG connection.
- Add and prove an actual resource-server `DPoP-Nonce` challenge/
  issuance flow, and a strictly vetted public HTTPS reverse-proxy
  binding for the PDS's exact origin/HTU. Current test gets a nonce
  from the existing provider OAuth nonce service.
- Complete full ATProto direct scopes/permission-set expansion, app
  registrations and consent ceremonies, protected Jena generation CAS,
  full PDS auth/sessions/blob/record API, and deployed Redpanda/native
  event replay.
- Perform real multi-replica end-to-end authorization, grant
  revocation, key rotation, Redis node loss, PostgreSQL PITR, stalled
  commit, p95/p99 and cost acceptance. Do not open registration before
  those gates are independently reviewed.

Primary specifications: RFC 9449 (§4.3, §7, §11.1) and
https://atproto.com/specs/oauth and
https://atproto.com/specs/permission .
