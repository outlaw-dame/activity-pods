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

## Upstream SemApps mutation holding fence (November 2026)

The installed SemApps account service has multiple *independent* methods
that change a password, reset token or stored native identity. The broker
must not allow them to bypass a pending canonical credential epoch simply
because signup is still CLOSED. The always-registered
`account-enrollment` middleware now checks **six** native account
actions before the upstream action handler executes:

- `setPassword`, `setNewPassword`, `generateResetPasswordToken`,
  `updateAccountSettings`, `deleteByWebId`, `setTombstone`.

For `updateAccountSettings`, upstream SemApps reads the WebID from
broker metadata, so the guard does too; the other five use their WebID
parameter. Every guard performs a **fresh, uncached, bounded no-retry**
private `auth.account.findByWebId` lookup with isolated broker metadata.
If lookup fails, mismatches, is missing or finds an enrollment marker
(including a malformed marker), the mutation fails **before** downstream
storage is touched. A previously enrolled but still unreleased owner
cannot use a reset/delete action to circumvent the native PostgreSQL v3
password trigger or canonical credential pending state.

Existing unmarked legacy account behavior remains unchanged; this is a
holding fence, **not** a new authenticated password-change mechanism
or proof of independent monotonic custody. A physically restored account
that *loses* its marker requires the independent credential head and v3
SQL enforcement; this broker guard **alone cannot prevent a stale
restored account from downgrading** and is not a basis for release.

The new real Moleculer broker regression calls all six action entrypoints,
verifies zero mutation-side effects for valid/malformed enrollment markers,
strict lookup isolation/fail-close and no retries, and verifies that
unmarked legacy operations remain callable. It runs as part of the
existing dependency/lint acceptance.

## Real SemApps service + PostgreSQL18 defense-in-depth proof

A dedicated ATProto/Fuseki isolated credential workflow now loads
`paper-local-native-auth.sql` and credential authority **v1, v2, v3**
into the same real PostgreSQL18 instance before creating the actual
`@semapps/auth` 1.1.4 `auth.account` service with the restricted
native database adapter.

The test persists a real bcrypt password, attaches the coordinator's
reserved WebID and enrolls that existing account at canonical credential
epoch 1. It then calls the **real upstream SemApps handlers** for
`setPassword`, `setNewPassword`, `generateResetPasswordToken`,
`updateAccountSettings`, `deleteByWebId`, and `setTombstone`
and requires every one to fail with the unreleased enrollment mutation
code. It additionally calls the adapter *directly* to try a bcrypt
change and account deletion; PostgreSQL v3 must reject both. The same
bcrypt hash, signup reservation and epoch 1 must survive without
any native receipt being recorded. The preexisting login-fence test
also checks the account persists across broker restart and that
password comparison still uses real bcrypt.

This is an isolated production-configuration **negative acceptance**.
It does **not** perform a positive owner-approved password reset,
simulate approval by an external independently operated credential
head, activate the SQL in a live service, or open new signup.
`release=CLOSED`.

## Close generic account write and direct creation bypasses in production

The pinned SemApps auth.account service inherits insert, update and
remove Moleculer DB actions with generic id/data arguments. The
upstream account schema also exposes create and attachWebId as
independently callable broker actions. These are NOT the authenticated
Paper enrollment-completion route. A caller reaching these entrypoints
could sidestep the production auth.signup fuse, mutate account records
or bypass the six explicit password/reset/tombstone holding fences.

In production, the always-registered AccountEnrollmentMiddleware
refuses all five unscoped action names before the underlying handler.
Production mode is captured when the middleware is constructed.
Changing process environment afterward or spoofing broker metadata,
an admin flag, a WebID or a reservation marker cannot re-enable them.
Future positive signup must use a reviewed canonical coordinator,
not simply remove this check or flip a deployment flag.

Existing legacy owner operations with their own service logic,
including updateAccountSettings and setPassword, remain callable
for unmarked accounts. The explicit six upstream mutation routes
continue performing fresh enrollment checks for tracked accounts.

The production-mode regression uses an isolated real Moleculer broker
with no live accounts or credentials and proves all five generic/direct
actions never run despite forged privileged metadata. It additionally
checks runtime environment mutation cannot reopen the closed actions,
while approved legacy settings/password actions still work.

Scope: this guard controls public broker action entrypoints, NOT
internal service _update operations or raw adapters. Durable PG v3
native credential SQL, nonrewindable independent checkpoint custody,
real owner-authorized reset and hosted cross-protocol positive signup
are still required. Production signup and release remain CLOSED.
