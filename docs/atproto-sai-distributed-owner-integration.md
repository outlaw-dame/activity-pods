# Disposable cross-replica SAI authorization integration

**Release status: not activated outside disposable tests.**

The native `auth-agent.registerApp`, `upgradeApp`, and `removeApp`
continue verifying the actual Pod owner through the provider's
normal Solid-OIDC authentication and SAI workflow. They now call an
async proof adapter. When the new flag is **off**, or an application is not in the
approved native-ATProto SAI app allowlist, this delegates to the
original bounded process-local nonce and makes no Redis connection.
When enabled in a disposable test, the owner action issues a
cryptographically signed, scoped proof in Redis. Nested SAI
AccessAuthorization/DataAuthorization/AccessGrant/DataGrant hooks
verify the exact owner/application/request ID against shared Redis
when their request runs on another Moleculer process. They still
check SAI container membership, WebACL and canonical consent rules,
and never accept the copied ctx.meta token by itself.

A dedicated no-action Moleculer lifecycle service disconnects the
one lazily initialized Redis client per Node process at shutdown.
A single-flight guard prevents concurrent first requests from
opening duplicate connections. Redis uses an offline-queue-free,
bounded connection timeout and no unrestricted transport retries.
Failed connection/proof/revocation denies the protected mutation.

## Test-only settings

All these settings must be supplied together:

- `NODE_ENV=test`
- `APODS_ATPROTO_TEST_STORAGE_DISPOSABLE=confirmed`
- `APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED=true`
- `APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED=true`
- `APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL=redis://redis:6379/15`
- `APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY` = random 32-byte base64url secret

The source-controlled release gate rejects enabling the distributed
proof without the native SAI fence, and refuses all non-disposable
deployments. The runtime independently validates the marker and an
exact isolated loopback/container Redis DB15 target. No default
password, production secret or network fallback is supplied.
The actual SAI/RDF production gate remains closed.

Unit tests cover concurrent pool initialization, owner-impersonation
denial, cross-context scope checks, unsafe DSNs, credential outages,
and no Redis cost in the disabled path. The disposable G1 HTTPS
provider CI separately uses two Node processes with the *actual
runtime* adapter against Redis. A proof is valid only before parent
completion; wrong app/request and stale replay are denied.

## Remaining release acceptance

Real Solid-OIDC owner install, upgrade, removal and revocation must
run under this flag with SAI nested work deliberately dispatched
to different Moleculer nodes. Redis must use a separate restricted
ACL principal and isolated keyspace, not OIDC, general app or
federation credentials. Key rotation, Redis unavailability during
a mutation, long-running parent actions, stale-proof expiry and
multi-tenant capacity budgets also need real acceptance.

Only after the canonical PostgreSQL SAI/identitybinding authority
migration and signed-repository permission reads have passed can
the native storage release fuse be removed. This is not a passkey
or login-system change.
