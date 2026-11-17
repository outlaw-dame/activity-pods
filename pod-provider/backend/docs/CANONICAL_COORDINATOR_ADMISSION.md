# Local canonical coordinator admission

Status: disposable integration only. Successful browser signup and production
readiness remain unproven. No production release fuse is opened.

The existing authenticated coordinator can explicitly load
`ACCOUNT_COORDINATOR_CANONICAL_CONFIG` with `PAPER_ACCOUNTS_DISPOSABLE=confirmed`
and its existing test-only flags. Without that option the standalone proof is
unchanged. The integrated database must install, in order, account migrations
v1-v4, repository schema, AT canonical authority, pre-account reservations,
v4 reservation completion bridge, then `pg-canonical-signup-reserver.sql`.
Enrollment v6 is compatible and separately required for consent.

The private JSON file (regular file, current owner, mode 0600, <=16 KiB, no
symlinks) contains exactly `appClientId`, `reserverDsn`, `binderDsn`,
`hmacKeyBase64` (32 random bytes), and `hmacKeyVersion`. It accepts only the
existing loopback PostgreSQL proof endpoint 127.0.0.1:5548, database
`atproto_signed_repo_proof_test`, with distinct logins
`paper_account_reserver_login` and `paper_bridge_binder_login`. Provision each
login separately, inheriting only its corresponding NOLOGIN role with INHERIT
TRUE, SET FALSE, ADMIN FALSE. Keep the file out of Git and provider processes.
The approved app scope is derived from the exact configured HTTPS client URI.
The proof currently retains its fixed https://paper.example.org provider identity;
it is not a deployment configuration for arbitrary hosts.

Execution order:

1. Existing restricted pre-account authority reserves username and execution fence.
2. Commit pre-account side-effect fence. Replays receive no execution credential.
3. Existing account lifecycle reserves the canonical account and signup journal.
4. Restricted binder binds the original reservation to that exact canonical scope.
5. Existing lifecycle commits canonical `reconciliation_required` side-effect fence.
6. Request the signed dataset ticket. Existing provider signup consumes the one-time
   execution claim before creating identity side effects.

The new SQL migration makes both issuer lease checks and signup consumption
require the same bound, fenced canonical operation. An unbound reservation, or
a committed binding whose canonical fence was not acknowledged, cannot proceed.
The reserver cannot write identity, evidence, completion or grant fields; its
connection is rechecked for exact table/column/function privileges before each
transaction. The binder uses the existing independent role admission check.
Pool borrowing and SQL waits are bounded; no admission mutation is retried.
A dropped HTTP response prevents a later issuer request after admission returns.

If any commit or binding acknowledgment is uncertain, preserve both journals and
reconcile that operation. Do not generate a new idempotency key, drop an account,
release a username or replay identity creation. There is deliberately no automated
recovery that could mint a second identity.

Verification: `tests/canonical-coordinator-admission-node.test.cjs` uses actual
PostgreSQL 18 and restricted principals, including concurrent admissions, one-time
claims, denied unbound tickets, privilege drift, lost committed bind response,
production refusal and private configuration validation. It creates a unique
disposable database and logins and removes only its own resources. It does not
prove the complete HTTP worker + issuer + browser chain.

Remaining: run the integrated worker and actual provider in one local runtime;
connect private enrollment issuance and browser consent; use an immutable native
SAI manifest; complete genuine provider-key PDS verification and canonical completion;
then prove normal login/app return and restart/failure recovery. The permanent
pending-account marker must not be manually cleared to get a successful login.
