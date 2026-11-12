# Cross-replica SAI owner proof — review-only candidate

The native SAI before-hook currently uses a process-local, 4,096-entry
authorization map. It fails closed when an otherwise legitimate nested
Moleculer action is dispatched to a different process. Accepting copied
`ctx.meta` as proof would be an authorization vulnerability.

The separate `atproto-sai-distributed-owner-proof.js` candidate adds a
Redis-backed proof, bound to the exact authenticated owner WebID,
approved application URI and original Moleculer requestID with a
256-bit HMAC key. The issuer creates a fresh 256-bit capability only
from a directly authenticated owner (no impersonated user).
It reserves one of at most 4,096 local proof slots BEFORE Redis I/O,
writes the HMAC digest using atomic `SET NX PX` with a 120-second
TTL, and deletes the proof key upon parent completion.
The verifier on another process performs an exact Redis read and
constant-time digest comparison. It never trusts metadata alone.
The verifier keeps no expanding memory cache. Expired or forged
proofs and Redis outages deny the operation.

Unit tests cover scope alteration, TTL expiration, weak secrets,
failed writes, bounded issuance, forgery and release. The disposable
G1 provider workflow includes a genuine Redis test: an issuer and
a second independent Node process share only the Redis state and
signed scope; the verifier rejects wrong app/request and, after the
issuer deletes the key, the same proof.

## Before activation

This module is **not connected to the current auth-agent or native
SAI hooks**, and no public route or production enable flag is added.
The release plan requires a separate Redis ACL credential scoped to
`paper:sai:owner:*`, a restricted signing-secret deployment only
to trusted issuing/verifying services, validated cross-replica
Moleculer parent context, secret rotation, availability/node-loss
tests, and a production-grade resource and cost model.

The capability is not a new login mechanism. The existing actual
Solid-OIDC owner authentication, WebACL checks, SAI container
membership, and canonical PostgreSQL consent authority remain
mandatory. The global native ATProto storage release fuse stays
closed until these gates and the real user-consent path pass.
