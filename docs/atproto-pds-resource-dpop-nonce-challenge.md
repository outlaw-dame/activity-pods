# ATProto PDS write resource-server DPoP nonce challenge

**Status: nonactivated, test-only. No production PDS route, signup release,
canonical storage cutover, or migration of existing accounts.**

The previous provider OAuth bridge required a server-minted nonce, but the
signed-write HTTP edge could not tell a client how to obtain one. A usable
resource server must differentiate an expired/missing DPoP nonce from a
bad token or a provider storage outage.

## Behavior

- The existing `oauth-dpop-nonce.verifyProof` validates a signed
  P-256 proof, issuer-verified access token `ath`, `cnf.jkt`, HTM/HTU
  and the Redis GETDEL nonce. An invalid, expired or already consumed
  nonce becomes the provider's typed `INVALID_DPOP_NONCE` error.
- The nonactivated PDS write gateway identifies that exact type and
  calls a **trusted provider-injected** `mintDpopNonce` function.
  The caller cannot provide the nonce or its audience. The provider
  binds issuance to the constructor-approved PDS origin.
- If the issuer successfully persists a valid nonce, the HTTP response
  is 401, `WWW-Authenticate: DPoP error="use_dpop_nonce"`, and
  `DPoP-Nonce: <opaque random value>`; response is `no-store` and
  has a bounded public JSON error. The client signs a NEW DPoP proof
  including that nonce and the unchanged access-token hash, then
  retries the original bounded CAS write.
- If nonce minting/storage fails, the gateway returns 503 **without a
  DPoP-Nonce header**, because it cannot safely advertise a nonce
  that it cannot verify. An invalid token/signature/jti binding is
  still 401 `AuthRequired` without a fresh challenge.
- The request-local post-commit `recheck()` reads current OAuth
  consent and canonical PostgreSQL grant and **does not re-consume
  the already accepted DPoP proof**. A revoked grant after signed
  commit remains an uncertain 503, not automatic write replay.

## Disposable real-service evidence

Backend CI pins Redis **8.2.11** and uses the existing provider JWT
issuer/introspector, DPoP verifier and OAuth consent services.
A local HTTP XRPC listener creates the provider authorization bridge
and exact resource nonce issuer. The test sends a cryptographically
valid signed DPoP proof *without a nonce*, checks the HTTP 401
challenge, retries with a fresh proof using the server's nonce, and
verifies one write and **only one signed DPoP validation on the
successful request**. Replayed nonce/DPoP, invalid OAuth scopes,
client/DID mismatch, and issuer-storage outage are denied.

The XRPC writer in this HTTP-only test is a disposable stub. Separate
real PostgreSQL 18 + upstream MST, canonical PG consent-lock and
persistent Jena recovery workflows continue to prove the signed
repository and outbox layer. Production must prove the combination
with real trusted reverse proxy, network and broker services.

## Production NO-GO

- No registration of the public write endpoint. Trusted broker
  nonce issuer, proven TLS/PDS HTU, DPoP origin, and distributed rate
  limiting remain to be deployed and accepted.
- The existing one-time GETDEL nonce design is intentionally stricter
  than RFC 9449's reusable nonce option. The API must document and test
  clients obtaining fresh nonces for independent writes.
- Full ATProto permission sets, OAuth client consent ceremony,
  protected Solid/Jena monotonic generation CAS, production
  least-privileged signing credentials, full PDS Lexicons and
  authenticated sessions, and native durable event delivery remain
  prerequisites.
- Complete exact-deployment, multi-replica failure, replay and
  performance/cost acceptance before considering a source-controlled
  release-fuse change.

Reference: RFC 9449 §9 (Resource Server-Provided Nonce), §4.3, §7.
