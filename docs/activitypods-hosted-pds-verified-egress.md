# ActivityPods hosted-PDS proof — fixed-origin HTTPS egress

**Status: nonactivated provider-side integration. Production new-account
registration, PDS HTTP routing and protected Solid/SAI release fuses remain
closed. No existing account adoption or migration is enabled.**

## Security boundary

The prior hosted genesis attestation verified signed CAR/MST and state but
depended upon an injected `requestPds` callback. The provider previously
had no source-controlled HTTPS transport to ensure the response actually
came from the approved PDS rather than a redirect, private endpoint,
attacker-controlled DNS response or trusted-fixture HTTP server.

`fixed-origin-pds-https.mjs` is a provider-scoped, read-only XRPC transport
that makes a **real TLS connection** and returns the constrained response to
`createHostedSignupPdsAttestation`. It requires:

- A **canonical HTTPS origin** fixed at construction; no credentials, query,
  path, fragment or literal IP-hostname. Production origin uses the default
  HTTPS port. No URL comes from a public signup request.
- An explicitly approved set of global-unicast IP addresses. Each DNS
  answer must be global and a member of that operator-controlled set.
  A response mixing approved and unapproved answers is denied in its
  entirety. The selected address is pinned via Node's socket `lookup`
  callback; the TLS connection cannot silently resolve a different host.
- Normal **TLS certificate chain and hostname/SNI verification**, with no
  `rejectUnauthorized:false`, no system proxy rewriting and no implicit
  HTTP redirect. A trust-root override, resolver injection, nonstandard
  HTTPS port or loopback address is permitted solely in a **disposable CI**
  environment with multiple test flags.
- Only the three read-only Sync XRPC operations used for new-account
  attestation: `getLatestCommit`, `getRepoStatus`, `getRepo`. The
  parameter must be a syntactically valid `did:plc` and the path must be
  canonical with exactly one `did` parameter. No signed-in bearer header
  or private signing key is sent over this connection.
- Request deadline, bounded concurrent connections (default four), TLS
  header budget (8 KiB), response budget (256 KiB including CAR), and
  immediate cancellation of overlarge/error responses. Do not retry DNS,
  TLS handshakes or HTTPS requests automatically after failures.
- Stable error codes with no private account, DNS address, token or
  certificate material in user-visible errors. A prior successful proof
  cannot authorize a future signup after an HTTPS failure.

The transport does **not** decide account or SAI authority. Independent
PG signed-head verification, live HTTP CAR verification, Solid/Jena
projection and canonical PG consent must still agree. The existing v4
atomic completion later locks and checks canonical state.

## Disposable acceptance

The existing end-to-end new-signup PG18 test now starts an actual local
**HTTPS PDS listener** with a temporary certificate for the expected
provider hostname (issued at test time using OpenSSL). The fixture
approves only `127.0.0.1` under the explicit test-only gate and pins DNS
there, while keeping normal certificate validation and SNI checks on.

It exercises genuine secp256k1-signed genesis over TLS Sync XRPC, complete
CAR verification, pre-seal and post-seal evidence, canonical PG consent
and atomic account/journal completion, plus adversarial tests for
untrusted certificates, wrong TLS hostname, DNS rebinding/private IP,
unexpected query/hostname, HTTPS redirects to metadata endpoints,
oversized responses and production fixture refusal. Temporary keys,
synthetic PG schemas and roles are destroyed after the test.

## Deployment and operational acceptance not yet complete

This code is intentionally **not registered as a runtime provider
service or public signup route**. A production service composition must
supply the trusted origin and managed DNS/IP allowlist from operator-side
configuration, rotate addresses safely (never from signup input), and
instantiate a bounded connection policy with deployment-specific network
egress rules. This is one defense layer, not a substitute for network ACLs.

Remaining principal gates: real Solid-OIDC/ATProto OAuth and DPoP
verification, externally proven DID/PLC + signing-key custody, native
protected Fuseki generation CAS, canonical PG least-privileged writer
role and release rollback, complete PDS Lexicon endpoints and sessions,
outbox publication to Redpanda, cross-node failover and controlled
performance/operating cost testing. **No production signup guard or
storage release constant may be changed by this integration alone.**

Primary references:
- https://nodejs.org/api/https.html
- https://nodejs.org/api/tls.html
- https://nodejs.org/api/dns.html
- https://atproto.com/specs/xrpc
- https://atproto.com/specs/sync
