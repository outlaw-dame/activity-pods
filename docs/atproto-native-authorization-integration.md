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
