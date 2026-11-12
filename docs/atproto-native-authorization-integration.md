# ATProto repository permissions: native integration

This document tracks the work needed to connect a managed ATProto repository to the existing ActivityPods identity, Solid-OIDC and SAI services.

## What is implemented

The existing SAI AccessAuthorization, DataAuthorization, AccessGrant and DataGrant services now have a pre-write consent check. For an approved application, a grant change looks up the canonical account using a selective query in the settings dataset, reads that application's repository-consent record from the user's own Jena dataset, and blocks an active consent before the LDP resource can change. A separate read confirms that the change persisted. An ambiguous or failed update rejects the original SAI operation.

The consent query builders are shared with the per-Pod Fuseki proof. Normal grant operations for other apps do not query Jena. There is no whole-account scan or background loop.

The PostgreSQL proof includes a separate ticket issuer. It reads the exact live recovery lease and signed repository head, verifies the actual signed CAR and current SAI grant using trusted provider callbacks, then checks the lease again before signing a short-lived operation ticket. The PostgreSQL lease epoch and SAI consent revision have separate meanings.

Solid-OIDC now has a signed ES256 DPoP verifier. It validates the method, URL, token hash, signing key, and confirmation thumbprint. Replay detection uses an atomic Redis SET NX with expiry on the provider's existing Redis connection, shared across Moleculer workers. The same HTTP request can pass both authentication and authorization without being mistaken for a replay.

## Controls and deployment

The native SAI guard is OFF by default. Its integration-environment configuration is:

- APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED=true
- APODS_ATPROTO_SAI_FENCED_APPS: comma-separated approved client URLs, maximum 32

The Solid-OIDC DPoP verifier is independently OFF by default:

- APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED=true

DPoP enforcement affects the existing provider's Solid-OIDC authentication handlers. Before enabling it, verify how the actual provider issues tokens and how the reverse proxy reconstructs the public request URL. Older clients may not send a valid proof.

The PostgreSQL ticket issuer remains limited to explicitly disposable proof environments. No public ticket-mint endpoint or production repository writer is registered.

## Performance constraints

A relevant SAI grant mutation takes at most one indexed settings lookup (LIMIT 2), one read of a single consent subject in the owner's dataset, and, if active, a container lookup, one conditional Jena write and one bounded read-back. It never enumerates Pods, performs cross-Pod search, opens a PostgreSQL transaction across network calls, or retries indefinitely. Unrelated SAI apps bypass the database work.

A DPoP replay key is a fixed-length hash stored with a short Redis TTL. A Redis failure denies proof validation rather than silently falling back to process-local state.

A successfully blocked consent stays blocked even if the later grant mutation fails. Re-authorization must use fresh user consent and a strictly newer revision; this code does not automatically restore access.

## What still prevents release

This is not yet a production-ready PDS rollout. Before enabling the new code, we need:

- Atomic enforcement at the underlying SemApps LDP/triplestore mutation boundary. Direct LDP resource actions, migration writers or arbitrary triplestore updates may bypass the service hooks. The identity-binding full-resource PUT/DELETE race also remains.
- A real installed SAI DataGrant shape and user-consent ceremony for repository access, plus a complete grant issue, replace, uninstall, revoke and delete audit. A provider ticket is not user permission.
- Integration against a running ActivityPods provider to verify the exact per-user dataset and named/default graph used for protected LDP identity bindings and SAI resources.
- A private provider orchestration path that obtains current PostgreSQL claims, signs tickets and invokes the fenced per-Pod writer; no caller-selected lease epochs.
- An actual Solid-OIDC issued DPoP-bound ID token tested over HTTP, with reverse-proxy URL handling, shared cross-process replay rejection, clock skew and Redis outages.
- Four independent worker processes, process kills, lease expiry, network partitions, rate limits, connection-pool budgets and rollback tests.
- Production PostgreSQL migrations, least-privilege roles and a safe deployment and rollback plan.

Production signup and repository-readiness gates remain closed until these checks have real evidence. Passing a disposable Jena test does not by itself prove deployed authorization coverage.


## Low-level LDP guard and authorization ordering

The next integration branch adds two changes that can be reviewed separately from production activation.

First, the native SAI pre-write barrier checks the authenticated Pod owner, the exact grant or authorization target container, and current WebACL permission before it updates the consent record. An app's impersonatedUser metadata does not count as a user-approved SAI grant change. A denied or misrouted request must not be able to block somebody else's active repository simply by triggering a service before-hook. These checks run only for explicitly approved apps and never scan accounts.

Second, the existing SemApps LdpService supports hooksResource and hooksContainer on its internally created ldp.resource and ldp.container services. Those hooks now reject ordinary LDP mutations of resources under a user's identity-bindings container when native ATProto fencing is enabled. This covers direct Moleculer resource PUT, PATCH, DELETE and CREATE calls, and common container POST, attach, detach and delete actions that would otherwise bypass the identitybindings service. It does not change unrelated Pod resources and adds no database query to the normal write path. Tests check the wiring against the exact installed SemApps package version.

**This is not a complete database authorization boundary.** SemApps also exposes triplestore.update, triplestore.insert and triplestore.dropAll, and allows privileged provider writes using the system identity. A direct SPARQL update, an offline migration, or an administrator with Fuseki credentials can bypass a JavaScript hook. The protected writer still needs an enforceable Jena graph/dataset access policy and separate least-privilege credentials, plus end-to-end testing with privileged calls deliberately attempting to cross that boundary. No setting in this branch claims these bypasses are closed.

The new SAI preauthorization is deliberately strict: it requires the authenticated owner, rather than accepting an app identity or a self-asserted webId action parameter. Internal grant-management calls that do not carry the real owner context will be denied when enforcement is enabled. That behavior must be exercised through the actual owner consent and app-removal flows before production rollout; adding an isInternal flag or trusting arbitrary Moleculer metadata would defeat the goal.

The release gate remains closed until the installed provider has tests that establish these behaviors with enforcement enabled.


## Focused hardening audit: state, memory, performance and cost

The implementation has been reviewed with the same constraints that motivated moving Group control-plane work out of the expensive ActivityPods request path. No new account-wide scan, unbounded pagination, per-request database transaction, persistent user cache, background polling task or silent retry is introduced here.

**LDP writes:** the disabled gate returns immediately. With the gate enabled, a single parsed provider base URL is reused; each affected URI is parsed with bounded length and at most four decoding passes. Direct and double-encoded protected paths, encoded separators and parent-container deletion cannot bypass the check. Normal unprotected resources are not scanned and do not query Moleculer, Jena, PostgreSQL or Redis. Malformed or oversized resource URLs can fail closed, which is intentional during protected mode. Operations on the provider or Pod storage roots are conservatively blocked; normal deletion and migration of protected Pods needs a separate privileged and audited protocol.

**SAI revocation state:** a single current approved-app configuration is cached (32 apps / 8 KiB maximum), refreshed when its environment value changes. The allowlist is not a growing map. Only the authenticated owner may modify approved-app permissions. The fence is written to the owner's dataset and read back before continuing, so a successful HTTP response with a nonmatching SPARQL WHERE clause cannot be treated as a successful revocation. The active grant revision cannot be restored automatically if a later LDP action fails. The seven-or-fewer sequential broker calls share one 12-second monotonic deadline; each call has a timeout no longer than five seconds. No blind retries occur during a security-sensitive mutation.

**Solid-OIDC and DPoP:** the replay check uses the existing OIDC Redis connection and Redis SET NX, not an in-process replay set. A request-local WeakMap holds one fixed-size SHA-256 fingerprint rather than raw JWT and DPoP strings. Its weak keys do not keep completed requests alive. Service shutdown disconnects Redis, and a failed startup after connection creation disconnects and drops the provider reference. An absolute or protocol-relative HTTP request target cannot choose a different DPoP origin. The replay TTL is 130 seconds: Redis key count grows approximately with accepted DPoP requests per second multiplied by 130, so realistic traffic and cost still need to be measured before the flag is enabled. Redis eviction of replay keys is not an acceptable capacity strategy; exhaustion must fail closed.

**What this does not prove:** static review and CI regressions cannot establish leak-free behavior at every workload, cost per million requests, or maximum throughput on deployed hardware. The installed provider still needs repeated startup/shutdown and load/heap profiling with the native enforcement flags enabled. A privileged triplestore/Fuseki actor still bypasses these LDP hooks. The existing permissive OIDC client-origin CORS behavior requires an independent protocol-aware review before DPoP production enforcement. Neither that policy nor production provisioning has been changed in this hardening pass.

The completed verification belongs to the exact commit reported in GitHub Actions, not merely the pull request's draft or mergeability state.


## November 2026 security and capacity evidence

The disposable provider exercises native SemApps HTTPS signup, real SAI,
Jena TDB2, Redis, OIDC authorization code with PKCE, signed DPoP-bound ID
tokens, and DPoP replay denial. It is **not** production-scale traffic.

### Measured results

On e794071bc721e33a3b8e60878c1deb6ff2a80537, Backend checks passed
158 Jest suites and 1,287 tests. Native Solid-OIDC HTTP acceptance and
private Docker Compose boundary checks also passed.

The Node 22.23.4 GitHub runner reported these disposable microbenchmarks:

| Case | Operations per second | Post-GC heap delta |
| --- | ---: | ---: |
| LDP guard disabled (50k calls) | 2,925,782 | 4,024 bytes |
| Enabled, ordinary unrelated LDP path (50k calls) | 494,200 | 61,520 bytes |
| Enabled, protected resource denied (10k calls) | 59,860 | 39,448 bytes |
| OIDC client-origin CORS checks (15k calls) | 307,934 | 11,920 bytes |

These figures measure in-process functions, not HTTP throughput or
long-duration leak behavior.

The first real Redis run accepted 512 of 536 simultaneous grant token
issuances, rejected 24 above the cap, and removed 532 legacy revocation
pointers in bounded batches. It ran in a single process. Follow-up
four-process contention, interrupted-revocation, duplicate-token and
Redis replay-key MEMORY USAGE tests are separate acceptance requirements
until they have passed CI on their exact commit.

### Thirty-day scale assumptions, not a billing quote

One million accounts with one affected grant change each per month
would generate an estimated four million Jena calls and seven million
broker calls per month, averaging 1.54 Jena calls per second or 15.43 at a
tenfold traffic peak. The model assumes every change affects an approved
app with active consent. Unrelated grants make no extra RDF calls.

At 1,000 DPoP-protected requests per second, a 130-second replay TTL
implies approximately 130,000 live Redis keys and 2.592 billion replay
reservations in 30 days. Actual RAM must include key overhead and Redis
allocator behavior. Expiring replay keys must not be evicted early or
replay validation will become unsafe. Real Redis memory sampling now
supplies a bounded empirical allocation figure.

The cost model deliberately leaves dollar pricing blank until real host
CPU, memory, network, storage, backup and service rates are known.
CI runner measurements are not production hardware sizing.

### Privileged RDF storage: production release blocked

The current SemApps triplestore uses broad rights over the same
per-user Jena dataset as managed identity bindings and consent state.
A privileged direct SPARQL update bypasses JavaScript LDP hooks.
Apache Jena supports dataset and endpoint ACLs, but its documented
graph-level authorization mechanism protects read-only datasets, not
write privileges at individual RDF subjects.

Therefore this branch has an explicit source-controlled release gate.
Enabling native ATProto SAI fencing in production rejects provider
startup until the canonical consent and signed-repository authority is
stored behind distinct, limited write privileges. Startup refuses activation in production, development, or an unset NODE_ENV.
A disposable test provider requires both NODE_ENV=test and the explicit
APODS_ATPROTO_TEST_STORAGE_DISPOSABLE=confirmed marker; the ordinary Docker
Compose production file does not set that marker. An administrator able to
change runtime configuration can still defeat a test-only environment
exception, so production infrastructure must additionally enforce deployment
policy and least-privilege access. An operator with process configuration or database
administration privileges cannot be constrained by this check alone.

A viable design keeps Jena as the Solid RDF projection and moves
canonical repo/consent state either to an isolated protected Jena
service or to a PostgreSQL control-plane table with a restricted
writer role. Native SAI revocation must commit the canonical blocked
revision before modifying a grant. An ordinary SemApps triplestore
caller must not be able to forge a readiness epoch, root CID or
active permission. Crashes across PostgreSQL and Jena must remain
fail-closed and repairable.

Before removing the source-controlled gate, require real deployed
negative SPARQL tests, owner consent and uninstall scenarios,
broker credential isolation, concurrent revocation/projector crash
recovery, sustained heap/RSS and pool profiles, and a costed
deployment configuration. No SPARQL text filter can replace a
storage-level permission boundary.


### Follow-up acceptance and hardening

The next live-provider pass exposed an important difference between direct
SAI resource actions and an authenticated app-upgrade ceremony. Moleculer
child actions can use system WebID to perform a provider-owned LDP write,
even when the original HTTP request was from the Pod owner. Allowing any
system WebID would be unsafe; checking only the child WebID also breaks
legitimate upgrades.

A reviewed interim fix associates the authenticated owner action with a
256-bit random proof, the exact app identity and Moleculer's request ID.
Nested SAI grant writes must carry the matching proof. The entry is removed
when register, upgrade or uninstall completes and is accepted for no more
than 120 seconds. The map has an absolute maximum of 4,096 in-flight
authorizations. A forged nonce, mismatched app or a different request ID
cannot revoke consent. Tests model Moleculer 0.14's actual metadata and
request-ID inheritance, rather than depending on a parentCtx property that
is not stored on child contexts.

This interim proof is process-local. Calls routed to a different provider
process correctly fail closed, but distributed operation is therefore not
ready for deployment. The final design must carry a verifiable,
request-scoped, least-privilege permission across nodes without accepting
caller-supplied metadata as an authority. Authorization and revocation
must still commit before the native grant mutation.

The disposable Redis concurrency test now uses an unpredictable per-run
key prefix and a bounded SCAN/UNLINK cleanup. It no longer calls FLUSHDB,
which could destroy unrelated keys in database 15. Its four worker
processes use exactly the same test namespace; no test process can choose
the production Redis database or omit the disposable proof flags. The
independent worker and interrupted-revocation checks are part of the
test and must be accepted by exact-head CI.

Two earlier CI failures must be interpreted separately: a native HTTP
signup stalled waiting for SemApps key-container readiness, while a
distributed node-loss proof reported a successful fault run but exited
nonzero before the acceptance assertion. Neither should be dismissed as
an application error without a repeatable diagnosis. The latest commit
and workflow runs, not those historical results, determine the pass/fail
status of the current candidate.


### Final security-review follow-up: provider entrypoints and OIDC errors

The official Moleculer fabric launcher checks the protected-storage release
fuse before spawning **any** service group. The generic triplestore continues
to check independently during module initialization. This closes the normal
multi-service deployment path in which a service group does not load the
triplestore module. Direct alternative launchers are not proof of isolation:
operators must keep production startup commands and configuration under
review, and the storage boundary itself remains unreleased.

The native Solid-OIDC HTML error renderer now escapes client-controlled error
field names and values, caps the number and size of displayed fields, and
logs only a bounded error code and numeric status rather than arbitrary
request metadata. This prevents reflecting attacker-supplied markup in an
OAuth error response and avoids logging token-bearing exception objects.
The provider's current one-year ID-token lifetime, existing ID-token use by
resource handlers, and automatic OIDC scope grant remain separate security
and compatibility decisions. These need a migration plan and real client
acceptance before shortening lifetimes or changing scope issuance; no
silent authentication cutover is included in this branch.
