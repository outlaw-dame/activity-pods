# Durable restricted browser enrollment

Production remains CLOSED. This is an explicit local-runtime component, not an
autoloaded signup route or evidence of successful browser signup. It adds the
missing consent session boundary without creating another canonical account.

## State and security contract

Migration `paper-account-postgres-candidate-v6-enrollment.sql` attaches one session
to the existing signup operation after its canonical account has reached
`provisioning`. The existing provider/app/operation and request/idempotency HMACs
must match. No session can be rotated or reissued for that operation, including
after expiry or an unknown database acknowledgment.

Only SHA-256 domain-separated hashes of a random 256-bit cookie and its derived
CSRF token enter PostgreSQL. The cookie is host-only, Secure, HttpOnly,
SameSite=Strict, Path=/ and valid for ten minutes. PostgreSQL owns expiry. The
configured frontend origin, application client, application resource and exact
return URI are bound to the operation. The return URI is retained for future
completion; these endpoints never redirect or issue a normal JWT.

The HTTP factory exposes only GET `/api/signup-enrollment` and POST
`/api/signup-enrollment/consent`, with restricted action mapping, exact-origin
credentialed CORS, bounded JSON input and no-store responses. Origin and cookie
come from actual request headers. Body-supplied owner, dataset, app and
`acceptAllRequirements` fields are rejected. Owner WebID and username come from
the canonical PostgreSQL account. The native adapter independently matches the
private auth account and its pending enrollment marker before invoking the
existing `auth-agent.registerApp` action with fresh, trusted owner metadata.

Required rights must all be selected; optional rights are never automatically
selected. Unknown and duplicate selections fail. A trusted provider loader must
supply sorted-independent required/optional identifiers and a SHA-256 `revision`
of the **resolved permission semantics**. Hashing only identifiers or trusting
`dc:modified` is insufficient. The loader is called again before claiming consent;
a changed snapshot fails closed. A production integration must also ensure native
grant creation consumes that same immutable permission snapshot. The existing
native action independently fetches its inputs, so this component alone does not
prove that cross-store/remote-manifest invariant. Use a provider-controlled,
immutable app manifest in the local rehearsal until that integration is verified.

PostgreSQL atomically changes `awaiting_consent` to `consent_claimed` before the
native mutation. A competing request loses the CAS. Timeout, process loss or an
unknown native result leaves the claim fenced; there is no automatic reset/retry.
A successful native result records only a receipt (`consent_recorded`), never a
completion attestation. The recorded URI is the native app-registration receipt,
not the canonical access-grant URI. A database constraint prevents the existing
completion CAS from marking an enrolled operation ready until consent is recorded
for the same application; all independent completion checks still apply. Refusal records `denied` without invoking native SAI.
Current native grant verification and canonical completion remain separate gates.

The SQL login inherits only `paper_enrollment_runtime`, with INHERIT TRUE,
SET FALSE and ADMIN FALSE. It has function execution but no direct account or
journal table/column access, schema creation, role administration or owner access.
Admission is rechecked on the same borrowed connection as each operation. The
caller must construct a bounded pool (connection and statement timeouts, small
maximum). Connection acquisition, query and external dependency waits are bounded; late
connections are discarded. HTTP actions cap in-flight calls and queue lengths; no mutation retry is
performed. Unknown SQL outcomes discard the connection.

## Local runtime integration

`makeBrowserEnrollmentService` takes the broker, restricted pool, provider/app
policy, private 32-byte CSRF key and trusted `loadRequirements` function. It returns
`schema` for explicit broker registration and a process-local `issue` method for
the trusted signup coordinator. Issuance is deliberately absent from HTTP and
Moleculer actions. Its `setCookie` callback must write the actual response header;
returned JSON contains no cookie credential.

All operations require `NODE_ENV=test`, `PAPER_ACCOUNTS_DISPOSABLE=confirmed`,
`PAPER_BROWSER_ENROLLMENT_DISPOSABLE=confirmed` and `fixtureOnly: true`. These flags
cannot enable production. The current staging launcher still rejects disposable
flags; this factory has not been added to that production-shaped profile.

Still to connect:

1. The real coordinator's existing reservation-to-v4 binding and identity result,
   so issuance uses the same durable operation and cannot trust browser HMACs.
2. The provider-owned immutable app manifest loader, frontend consent screen and
   credentialed HTTPS request/return transaction.
3. Real native SAI storage and current-grant readback; signed hosted PDS and
   protected projection checks; canonical completion and reviewed activation.

Do not manually clear `signupReservationId`, infer completion from a consent
receipt, call the native mutation again after a claimed result, or enable mock
identity fallback to obtain a successful signup screenshot.

## Evidence

`provider-browser-enrollment-node.test.cjs` uses PostgreSQL 18, two independent
connection pools, a restricted SQL login, a real Moleculer broker and HTTP gateway.
It covers CAS races, replay, changed permission semantics with unchanged IDs,
required/optional/refused consent, expiry, wrong application/origin/owner input,
CSRF, duplicate cookies, denied arbitrary-action routes, privilege drift, unknown
native acknowledgment and the production fuse. The native SAI action and account
identity records are fixtures in this test. It is neither a browser TLS test nor
successful end-to-end signup acceptance.

The workflow `provider-browser-enrollment.yml` reproduces this acceptance with a
pinned PostgreSQL image. Locally, the test reads a private JSON `databaseUrl` for
the disposable `paper_local_plc` database on 127.0.0.1:5549, creates a uniquely named
test database/login and removes only its own test resources. It never clears or
migrates the existing PLC database.

### Disposable provider verification

The local provider can verify an operator invitation before account creation.
Use this mode only for an operator-approved disposable username and email.
The operator checks who receives the invitation. Possession authorizes one
signup for that identity at the specified app and provider within two minutes.
This rehearsal does not verify ownership of a public email mailbox.

Construct the disposable provider services with
`makeLocalBrowserSignupServices`. Pass the operator's **public** Ed25519 key,
distinct verifier and redeemer pools, the transaction encryption key, and the
configured app bearer in addition to the existing enrollment settings.
Register the returned signup API in place of the ordinary signup API and
register the enrollment schema once. The operator retains the private key.

To issue an invitation, supply an owner-private regular JSON file containing
`privateKeyPem`, `username`, `email` and `scope`. The scope contains the exact
`providerId`, `appClientId`, `browserOrigin` and `returnUri` from the local
provider configuration. Use an unused output path on the operator workstation:

    NODE_ENV=test PAPER_ACCOUNTS_DISPOSABLE=confirmed APODS_ACCOUNT_COORDINATOR_DISPOSABLE=confirmed node scripts/issue-local-signup-invitation.cjs PRIVATE_INPUT.json PRIVATE_OUTPUT

The command creates a mode-0600 file. Give its contents to the intended local
tester through a private channel. In the configured provider login form at
`/login?signup=true&verified_signup=1`, enter the matching account details
and paste the invitation in the masked field. Verification returns a short-lived
HttpOnly transaction cookie. Only the coordinated create request redeems it.
A lost acknowledgment requires reconciliation. Never put the invitation in a URL.
