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
