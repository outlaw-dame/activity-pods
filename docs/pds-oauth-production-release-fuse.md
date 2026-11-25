# PDS OAuth source-controlled production release fuse

**Status: intentionally CLOSED. This change prevents issuance; it does not
activate the PostgreSQL or immutable-witness candidates.**

## Threat addressed

The provider still contains a Redis-backed OAuth grant, code, access-token and
refresh-family implementation. The opt-in PostgreSQL generation + witness
verification in `utils/oauth-pg-epoch-policy.js` is only qualified in
explicitly disposable Node test fixtures. Previously, with these variables
unset, production could call `enabled()` and silently choose the Redis-only
path. A restored Redis snapshot could then make a revoked credential appear
current. The unified signup fuse is independent and does not make that existing
OAuth issuer safe by itself.

## Boundary now enforced

- Outside `NODE_ENV=test`, the PG policy refuses all PDS OAuth minting
  pathways with HTTP 503 / `PDS_OAUTH_RELEASE_GATE_CLOSED`. Production and
  ordinary development cannot re-enable it using disposable env flags.
- `oauth-token.exchange` refuses before consuming an authorization code,
  refresh family or DPoP proof/nonce; direct `issueAccessToken` methods
  refuse before Redis consent reads or signer access.
- Owner approval refuses before consuming the consent challenge or PAR.
  Direct Redis grant upsert refuses before persistence.
- Direct authorization-code issuance and refresh issuance/rotation still
  require the epoch policy and therefore refuse outside disposable tests.
- Existing token introspection cannot return `active:true` even if a
  correctly signed old JWT and restored Redis grant agree. Revocation actions
  remain available so operators and owners can revoke previously issued
  authorizations without reopening issuance.
- Metadata, read-only authorization context, denial paths and ordinary
  unrelated Solid/ActivityPub services are not deliberately disabled.
  No source-only switch is provided to promote the issuer into production.

## Test evidence / release path

`tests/oauth-production-release-fuse-node.test.cjs` supplies signed JWT and
direct-action negative cases. The real PostgreSQL 18 + Redis 8.2 recovery
workflow runs those in addition to its existing independent witness proofs.
Unit tests are not equivalent to a live rollout.

Production enabling requires a separate reviewed source change after the
following *together* pass: canonical PostgreSQL consent/revoke operation
ordering; owner-bound SAI grant/replace/revoke/uninstall in live SemApps;
independently administered nonrewindable signed-head WORM custody; Redis,
PostgreSQL, Jena and PDS rollback tests; direct generic triplestore bypass
denial; hosted positive unified signup; performance/availability acceptance;
human security signoff. A configuration toggle, passing disposable test or
R2 bucket lock by itself must never open the release fuse.
