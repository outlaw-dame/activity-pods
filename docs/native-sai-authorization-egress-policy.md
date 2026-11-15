# Native SAI browser authorization: bearer egress and callback boundary

**Status:** provider frontend hardening; does not enable production signup.

The native ActivityPods `/authorize` UI uses an authenticated
`/.well-known/app-status` request and the application's Solid
Interop `interop:hasAuthorizationCallbackEndpoint`. Both involve
untrusted input: a user-editable WebID can advertise an OIDC issuer and an
external app can publish RDF metadata. Neither may dictate where the
frontend transmits its **locally issued session bearer token**.

## App-status request

`trustedAppStatusUrl` chooses the endpoint solely from the configured
`CONFIG.BACKEND_URL` origin. It rejects a WebID or
`solid:oidcIssuer` with another origin, malformed URL, credentials,
an unsafe scheme, or query/fragment injection. An authorized remote WebID
and cross-provider OIDC issuer need a separate, explicit
authentication route; the local-provider bearer must not be reused there.

The browser uses `redirect: 'error'`, `credentials: 'omit'` and
`cache: 'no-store'` and sends the local bearer **only after** URL
validation. This prevents redirect-based token egress and avoids
retaining private app status in a browser HTTP cache. Localhost and
loopback HTTP remain acceptable for explicit development configuration;
arbitrary plain HTTP providers or applications are not.

The app-status endpoint remains provider-authenticated; this change
does not make it public or grant app permissions.

## Application callback

Once actual Pod-owner SAI authorization has been verified, the
`/authorize` UI uses `trustedAppAuthorizationCallback` to validate
the app's RDF callback URL. It must be a canonical HTTPS URL with no
embedded credentials and the **same origin as the SAI application
resource URI**; explicitly configured loopback HTTP remains supported
for development. Relative URLs, custom schemes, origin-confusion URLs,
userinfo and malformed URLs are rejected. Same-origin callback query
and fragment components may be retained for the legitimate app's own
navigation state.

Applications whose callback lives on a different origin need a
separately reviewed trusted-callback registration or allowlist; do not
silently bypass this rule based on app RDF metadata or a signup
`redirectUri`. A rejected issuer/callback presents an error message
instead of leaving a blank authorization page or navigating insecurely.

## Verification and remaining production gates

The native SAI consent workflow runs the pure policy regressions,
JSX/syntax checks, and the full frontend build. The tests cover
identity/issuer origin confusion, bearer egress, URL credential injection,
unsafe schemes, arbitrary callback hosts, query/fragment handling and
loopback development behavior. Browser-level integration of local
login, actual provider SAI grants, app callback continuation and
exact-idempotency Paper/Entryway retry is still needed before production.

**No production signup release fuse, stored account authority or
cryptographic signer was changed.**
