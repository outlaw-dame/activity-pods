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
helper, actual provider signing handlers, ephemeral real secp256k1 keys, and the independently validating
reference directory pinned at `29f1a70ee9f6f80a25946cac103b2f745e371334`:
https://github.com/did-method-plc/did-method-plc/tree/29f1a70ee9f6f80a25946cac103b2f745e371334

The reference directory stores operations in real PostgreSQL. Acceptance covers
invalid signature rejection, signed registration, exact replay without duplicate
operations, DID document signing-key resolution, and directory-process restart
against the retained database. The same DID and provider signing handlers also
create a cryptographically verified PostgreSQL repository with signed CAR and
outbox; replay retains the original head. Unauthorized key access and signing
for a different DID are rejected. It does not test PostgreSQL-server restart.
The key and identity-binding storage used by this harness remains a fixture;
it does not prove real Pod key custody or complete signup.
The test HTTP listener binds only to 127.0.0.1; no public PLC writes or email occur.

Run `node --test pod-provider/backend/tests/atproto-plc-submission-node.test.cjs`
for HTTP failure and configuration coverage. `.github/workflows/local-plc-signup.yml`
reproduces real reference-directory acceptance. Its script requires explicit local
`NODE_ENV=test`, `PAPER_LOCAL_PLC_DISPOSABLE=confirmed`,
`ATPROTO_REPO_PROOF_DISPOSABLE=confirmed`, a pinned reference checkout, and private JSON containing a
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

## Enrollment authentication boundary

Delegated signup now records `signupReservationId` in the private auth account
in the same create operation that stores the password. Client profile input
cannot supply this field. A username is required before the coordinator's
one-time admission; email-only fallback must not bypass that admission.
The delegated action returns provisioning facts without generating a login JWT.

The broker middleware rejects password verification and JWT minting for any
account containing the enrollment marker, including malformed markers. JWT
verification also re-reads the private account and rejects a previously signed
token for an incomplete account. Missing/mismatched accounts and lookup failures
fail closed. Each token lookup is bounded to five seconds, without retries or
inherited HTTP routing metadata; no readiness result is cached.

This is a holding fence, not a completion implementation. No route clears the
marker and no environment flag authorizes activation. Do not manually remove it
to make browser acceptance pass. The next integration must provide restricted
owner enrollment/consent, the existing canonical PostgreSQL completion CAS, and
a reviewed single activation path tied to that committed operation. The existing
bootstrap proof cannot simply become a permanent login predicate: it compares
the bootstrap repository head, which legitimately changes after later writes.

Validation: `node --test pod-provider/backend/tests/account-enrollment-node.test.cjs`
uses a real Moleculer broker and SemApps RS256 JWT service with ephemeral keys;
account storage is a fixture. The signup regression suite verifies that delegated
signup makes no JWT call and persists the fence before identity creation. Neither
test substitutes for a successful real browser signup.
