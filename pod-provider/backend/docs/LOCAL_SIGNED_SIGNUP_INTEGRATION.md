# Local signed signup integration

Production release remains CLOSED. Successful provider/browser signup is not yet
implemented by this change. Do not remove the source-controlled signup gates or
set mock identity flags to turn this acceptance into an account-completion claim.

## Verified PLC integration

The provider's provisioning, submission and verification services now use one
validated PLC origin. Either existing environment name is supported:
`APODS_ATPROTO_PLC_DIRECTORY_URL` or `ATPROTO_PLC_DIRECTORY_URL`. If both are set,
they must identify the same origin. Plain HTTP is allowed only for loopback in
non-production; credentials, paths, query strings and fragments are rejected.

`APODS_ATPROTO_ALLOW_MOCK_IDENTITY=false` is respected outside production.
Production and real PLC submission always disable mock identity fallback.

A submission is confirmed only after the current directory operation exactly
matches the queued signed genesis, including its signature. The reference server
uses HTTP 400 for duplicate genesis; 400/409 alone never mean success. Requests
reject redirects, cap operation bodies at 16 KiB, and share one attempt deadline.
The existing durable scheduler owns bounded retries of the same signed operation.
Re-entering build-and-enqueue reuses matching pending signed bytes without another
signing RPC. Changed intent, mismatched confirmed DID, and rebuilding a completed
or failed identity are refused rather than silently creating a different genesis.
Remote response bodies and network exception details are not persisted in errors.
Corrupt persisted JSON is retained and fails closed instead of being deleted and
mistaken for an available account name.

The local acceptance script uses the actual provider PLC builder and submission
helper with ephemeral real secp256k1 signing keys and the independently validating
reference directory pinned at `29f1a70ee9f6f80a25946cac103b2f745e371334`:
https://github.com/did-method-plc/did-method-plc/tree/29f1a70ee9f6f80a25946cac103b2f745e371334

The reference directory stores operations in real PostgreSQL. Acceptance covers
invalid signature rejection, signed registration, exact replay without duplicate
operations, DID document signing-key resolution, and directory-process restart
against the retained database. It does not test PostgreSQL-server restart.
The test HTTP listener binds only to 127.0.0.1; no public PLC writes or email occur.

Run `node --test pod-provider/backend/tests/atproto-plc-submission-node.test.cjs`
for HTTP failure and configuration coverage. `.github/workflows/local-plc-signup.yml`
reproduces real reference-directory acceptance. Its script requires explicit local
disposable markers, a pinned reference checkout, and private JSON containing a
`databaseUrl` for `paper_local_plc` on 127.0.0.1:5549. It never clears an existing
database; each run creates a new ephemeral-key test identity.

## Remaining account-completion integration

This change does not supply provider key custody in the local harness, register
the candidate signed-repository service in the broker, replace the Redis PLC
submission scheduler with a canonical PostgreSQL worker, grant SAI permissions,
or issue a browser login token. Existing historical Redis confirmation records
are not migrated or retroactively reverified by this change.

Continue by connecting the real provider-owned key/signing boundary and PLC
resolution to the signed PostgreSQL repository authority. The same operation must
then pass protected RDF projection, current native SAI consent/revocation, hosted
signed CAR readback and the PostgreSQL account completion CAS before a successful
browser response. The existing `postseal-signup-completion-evidence.mjs` and
`postgres-signup-atomic-completion.js` candidates define these checks; their
fixture callbacks/booleans are not production evidence.

Unknown cross-store outcomes must retain their original identity and operation.
Do not create a second writer, bypass the coordinator admission, retry with a new
identity, or treat a passing PLC test as permission to open the production fuse.
